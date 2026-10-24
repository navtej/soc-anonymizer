#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "gliner2[local]>=2.1,<3",  # [local] = on-device inference (torch, transformers)
#     "openpyxl>=3.1",           # .xlsx / .xlsm
#     "python-calamine>=0.3",    # fast streamed reading of large .xlsx (Rust)
#     "rich>=13",                # progress display
# ]
# ///
"""
soc_anonymize.py - local, offline anonymizer for SOC exports
(Jira CSV/XLSX, SIEM JSON/NDJSON, Azure logs, CSV/XLSX cells that contain JSON).

Excel (.xlsx/.xlsm): all sheets incl. hidden ones; row 1 of each sheet is the
header. Books whose uncompressed sheet data is <= --xlsx-full-max-mb keep formatting:
comments, hyperlinks, string literals inside formulas and workbook metadata
(author etc.) are scrubbed; pivot tables are dropped because their cache holds
an unscrubbed copy of the data. Larger books are streamed row by row: values
only (formulas become cached values; comments/links/formatting are not copied). Numbers stored as numeric cells
(e.g. a phone number typed as 9814012345) are not touched.

Files are streamed, never loaded whole: CSV/TSV rows, log lines, NDJSON records and
the records of a JSON document (top-level array, or arrays under a top-level object
like Azure {"value": [...]}) are read, scrubbed and written one at a time.

Before anything is written, all inputs are pre-scanned: values of identity
columns (Assignee, Reporter, Tenant/Customer, Issue key/id, Assignee Id, Owner,
Computer ... also 'Custom field (Tenant Name)'-style Jira headers) are collected
into a lexicon together with obvious variants (tenant short names like 'Acme' /
'ACME' / 'AcmeHoldings', unique first and last names, issue keys of the same
Jira project). The startup log lists the columns recognised per file; use
--id-columns / --keep-columns to correct it and --terms for extra names.

Pipeline per string value:
  1. If the string is itself JSON -> parse, recurse, re-serialize (compact).
  2. If the column/key is an identity column -> pseudonymize the whole value.
  2b. Free text: every lexicon term -> the SAME token its column got, so a
      Summary/Description mentioning the assignee, tenant or a ticket key stays
      consistent with the Assignee / Tenant / Issue key columns (and across files).
  3. Deterministic regex rules (IPs, emails, GUIDs, SIDs, MACs, user paths,
     DOMAIN\\user, secrets/JWTs, internal FQDNs).
  4. Free text (Jira description/comments, SIEM message) -> GLiNER2-PII NER
     for names, addresses, phone numbers, etc.
  5. Optional (--review): a local LLM served by LM Studio (OpenAI-compatible
     API) reads the already-anonymized free text and flags anything that still
     identifies a person or the organisation. The LLM never rewrites text: only
     spans that literally occur in the string are accepted, and with
     --review-apply they are pseudonymized like everything else.
     Without --review-apply it is a dry run that only writes a report.

Pseudonyms are deterministic (HMAC with your secret key), so the same user /
IP / host maps to the same token across every file and correlations survive.

Usage (M2 Mac, everything local; uv resolves the inline dependencies):
  uv run soc_anonymize.py --prefetch          # one-time model download (no data sent)
  export HF_HUB_OFFLINE=1                     # then stay offline for every real run
  export ANON_KEY="$(openssl rand -hex 32)"   # keep this secret & stable
  uv run soc_anonymize.py data/*.csv data/*.json -o out/ \
      --domains corp.local,contoso.com --map mapping.json
  # or: chmod +x soc_anonymize.py && ./soc_anonymize.py ...

Optional: pin dependencies for reproducible runs
  uv lock --script soc_anonymize.py

Second pass with LM Studio (server on http://127.0.0.1:1234):
  uv run soc_anonymize.py data/* -o out/ --domains corp.local \
      --review --review-apply --review-report review.jsonl
"""
import argparse, csv, hashlib, hmac, io, ipaddress, itertools, json, logging, os, re, signal, sys, threading, time, warnings
import urllib.error, urllib.request
from pathlib import Path
from urllib.parse import urlparse

from rich.console import Console
from rich.markup import escape

csv.field_size_limit(sys.maxsize)
CONSOLE = Console(stderr=True, highlight=False)

def log(msg, style="dim"):
    CONSOLE.print(msg, style=style, markup=False)

def quiet_ml_libs():
    """Silence known-harmless noise from torch/transformers/huggingface_hub.
    Must run before gliner2 (and so torch/transformers) is imported."""
    os.environ.setdefault("TRANSFORMERS_VERBOSITY", "error")       # 'model of type extractor' notice
    os.environ.setdefault("TRANSFORMERS_NO_ADVISORY_WARNINGS", "1")
    os.environ.setdefault("HF_HUB_DISABLE_PROGRESS_BARS", "1")     # weight-loading bars
    os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
    warnings.filterwarnings("ignore", message=r".*torch\.jit\.script.*")
    warnings.filterwarnings("ignore", category=FutureWarning, module=r"(torch|transformers)(\.|$)")
    # macOS-only 'NOTE: Redirects are currently not supported in MacOs.'
    logging.getLogger("torch.distributed.elastic.multiprocessing.redirects").setLevel(logging.ERROR)

def run_cancellable(fn, on_cancel):
    """Run fn() in a worker thread so Ctrl-C is handled at once.

    Python only delivers Ctrl-C to the main thread *between* bytecodes, so a long
    torch/C call (one NER forward pass, an Excel parse, an LLM HTTP request) would
    otherwise hold it back. Here the main thread only waits, catches Ctrl-C
    immediately, runs on_cancel() (stop the display, delete the half-written file,
    flush reports) and hard-exits with 130 without waiting for the worker.
    A second Ctrl-C during that cleanup kills the process outright."""
    box = {}

    def target():
        try:
            box["ret"] = fn()
        except BaseException as e:            # incl. SystemExit from sys.exit() in the worker
            box["exc"] = e

    t = threading.Thread(target=target, name="anonymize-worker", daemon=True)
    t.start()
    try:
        while t.is_alive():
            t.join(0.1)
    except KeyboardInterrupt:
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        try:
            on_cancel()
        finally:
            sys.stdout.flush(); sys.stderr.flush()
            os._exit(130)
    if "exc" in box:
        raise box["exc"]
    return box.get("ret")

KEY = os.environ.get("ANON_KEY", "").encode()
MAPPING = {}  # token -> original (only written if --map is given)

# ---------- pseudonymization ----------
def _h(cat, value):
    return hmac.new(KEY, f"{cat}:{value.lower()}".encode(), hashlib.sha256).hexdigest()

def pseudo(cat, value):
    value = value.strip()
    if not value:
        return value
    # FQDN and short name of the same machine should get the same token
    h = _h(cat, value.split(".")[0] if cat == "HOST" else value)
    if cat == "IPV4":
        ip = ipaddress.ip_address(value)
        if ip.is_loopback or ip.is_unspecified:
            return value
        n = int(h[:8], 16) % (2**17)          # 198.18.0.0/15 benchmark range
        tok = str(ipaddress.IPv4Address(int(ipaddress.IPv4Address("198.18.0.0")) + n))
    elif cat == "IPV6":
        tok = f"2001:db8::{h[:4]}:{h[4:8]}"     # documentation range
    elif cat == "EMAIL":
        tok = f"user_{h[:8]}@example.com"
    elif cat == "GUID":
        tok = f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"
    elif cat == "MAC":
        tok = "02:" + ":".join(h[i:i+2] for i in range(0, 10, 2))
    elif cat == "ISSUEKEY":                    # still looks like a ticket key
        tok = f"TKT-{int(h[:10], 16) % 9_000_000 + 1_000_000}"
    else:
        tok = f"{cat}_{h[:8]}"
    MAPPING[tok] = value
    return tok

# ---------- identity fields (matched on the column / JSON key name) ----------
def norm_header(h):
    """'Custom field (Tenant Name)' -> 'tenant name'; 'userPrincipalName' -> 'user principal name'."""
    h = (h or "").replace("\ufeff", "").strip()
    m = re.fullmatch(r"(?i)custom\s*field\s*\((.*)\)", h)
    if m:
        h = m.group(1)
    h = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", h)            # camelCase -> camel Case
    return re.sub(r"[^a-z0-9]+", " ", h.lower()).strip()

# Ordered: first match wins. Patterns run on norm_header() output.
# Only columns whose WHOLE value is an identifier belong here; free-text columns
# (summary, description, comments ...) are scrubbed by lexicon + rules + NER instead.
COLUMN_RULES = [
    ("ISSUEKEY", r"(issue|parent|linked issue|epic link|outward issue link.*|inward issue link.*) key|issue key|parent|epic link"),
    ("ISSUEID",  r"(issue|parent) id"),
    # Azure / Sentinel / Defender identifiers
    ("TENANTID", r"((aad|home|resource|workspace|source|target) )?tenant (id|guid|uuid)|"
                 r"(customer|client|company|organi[sz]ation|org|directory) (id|guid|uuid)"),
    ("SUBSCRIPTIONID", r"((workspace|azure|source|target) )?subscription (id|guid)"),
    ("RG",       r"((workspace|azure) )?resource ?group( name)?"),
    ("WORKSPACE", r"workspace( name| id)?"),
    ("HOSTID",   r"(source )?computer id|(device|machine|agent|oms agent|mde device|mdatp device|aad device|azure ad device|sensor) id"),
    ("VENDORID", r"vendor original id|original alert id|provider alert id"),
    ("PROVIDER", r"(alert )?provider( name)?"),
    ("VENDOR",   r"vendor( name)?"),
    ("SYSTEM",   r"source system"),
    ("ENTITY",   r"(compromised|affected|impacted) entit(y|ies)"),
    ("DOMAIN",   r"upn suffix|nt domain|dns domain|domain( name)?|user domain|account domain|agent domain|"
                 r"login account domain"),
    ("USERID",   r"(assignee|reporter|creator|user|account|actor|caller|owner|analyst|approver|requester|"
                 r"watcher|participant|object|principal)s? id|account id|aad user id|user object id"),
    ("TENANT",   r"(tenant|customer|client|company|organi[sz]ation|org)( (display )?name)?|subscription name"),
    ("EMAIL",    r"e ?mail( address)?|mail|upn|user principal name|identity|"
                 r"(sender|recipients?|reply to|return path|envelope (from|to)|mail from|rcpt to)( e ?mail)?"
                 r"( address(es)?)?|(agent )?last logged in (upn|user ?mail)"),
    # NB: a bare 'DisplayName' is NOT a user column - in Sentinel it is the alert title.
    ("USER",     r"assignee|reporter|creator|owner|analyst( name)?|approvers?|watchers?|request participants?|"
                 r"user( ?name)?|account( ?name)?|target user ?name|subject user ?name|caller|initiated by|"
                 r"(created|modified|resolved|requested|reviewed|assigned|closed) by|requester|actor|"
                 r"user display ?name|src user|dst user|employee( name)?|full name|"
                 r"(sender|recipient|from|to)( display)? name|(agent )?last logged in user( ?name)?|"
                 r"process user|logins? user ?name"),
    ("HOST",     r"host( ?name)?|(agent )?computer( ?name)?|device( ?name)?|workstation( ?name)?|machine( ?name)?|"
                 r"src host|dst host|endpoint( name)?|asset( name)?|net ?bios ?name|fqdn"),
]
# Column-only categories: replaced in their own column, but NOT chased through free text
# (e.g. 'Microsoft' as VendorName should not wipe every 'Microsoft' from descriptions).
COLUMN_ONLY = {"PROVIDER", "VENDOR", "SYSTEM", "VENDORID", "ISSUEID", "GEO", "AWSTAG", "SERIAL"}

# Dotted field paths (Wazuh / Elastic exports: '_source.agent.name' as a CSV header, or the
# same nesting in JSON). Keys are lowercase path suffixes; the longest matching suffix wins
# and beats the leaf-name COLUMN_RULES. None = keep (not an identity field).
# Fields not listed here fall back to COLUMN_RULES on their last segment
# ('data.win.eventdata.targetUserName' -> 'target user name' -> USER).
FIELD_PATHS = {
    # Wazuh core
    "agent.name": "HOST", "manager.name": "HOST", "cluster.node": "HOST", "cluster.name": "HOST",
    "predecoder.hostname": "HOST", "host.name": "HOST", "observer.name": "HOST",
    "rule.mail": None, "organization.org": None, "organization.isp": None, "organization.asnorg": None,
    "data.srcuser": "USER", "data.dstuser": "USER", "audit.acct": "USER", "login_user.name": "USER",
    "effective_user.name": "USER", "user.name": "USER", "uname_before": "USER", "uname_after": "USER",
    "data.srcip": "HOST", "data.dstip": "HOST", "data.src_ip": "HOST", "data.dst_ip": "HOST",
    "hardware.serial": "SERIAL",
    # Windows eventdata
    "subjectdomainname": "DOMAIN", "targetdomainname": "DOMAIN", "samaccountname": "USER",
    "destinationhostname": "HOST", "sourcehostname": "HOST",
    # geo (Wazuh GeoLocation, GuardDuty remoteIpDetails)
    **{f"geolocation.{k}": "GEO" for k in ("city_name", "region_name", "real_region_name", "country_name",
                                            "country_code2", "country_code3", "postal_code", "area_code",
                                            "dma_code", "latitude", "longitude", "lat", "lon",
                                            "coordinates", "location", "timezone")},
    "city.cityname": "GEO", "country.countryname": "GEO", "country.countrycode": "GEO",
    "actor_location.country_code": "GEO",
    # AWS (CloudTrail / GuardDuty / VPC flow via Wazuh, also raw CloudTrail JSON in full_log)
    "aws.eventsource": "HOST", "sourceipaddress": "HOST", "aws.source_ip_address": "HOST",
    "aws.srcaddr": "HOST", "aws.dstaddr": "HOST", "useridentity.invokedby": "HOST",
    "privatednsname": "HOST", "publicdnsname": "HOST", "privateipaddress": "HOST", "publicip": "HOST",
    "ipv6addresses": "HOST", "ipaddressv4": "HOST", "clientprovidedhostheader": "HOST",
    "aws.accountid": "AWSACCOUNT", "aws.account_id": "AWSACCOUNT", "aws.aws_account_id": "AWSACCOUNT",
    "useridentity.accountid": "AWSACCOUNT", "recipientaccountid": "AWSACCOUNT", "responseelements.ownerid": "AWSACCOUNT",
    "log_info.s3bucket": "BUCKET", "bucketname": "BUCKET",
    "rolesessionname": "USER", "masterusername": "USER", "masteruserpassword": "SECRET",
    "instancedetails.tags": "AWSTAG", "instancedetails.tags.value": "AWSTAG",
    # Office 365 / Graph / GCP
    "office365.userkey": "USERID", "mailboxownerupn": "EMAIL", "ms-graph.assignedto": "USER",
    "ms-graph.actordisplayname": "USER", "principalemail": "EMAIL", "vminstancename": "HOST",
    "labels.project_id": "TENANT",
    # SentinelOne: the 'account' is the customer (Defender's AccountName is a user, so only these)
    "account_name": "TENANT", "site_name": "TENANT",
    **{f"{p}.{k}": "TENANT" for p in ("agentrealtimeinfo", "agentdetectioninfo")
       for k in ("accountname", "sitename")},
}

# Sentinel / Defender entity objects ({"Type": "account", "Name": ..., "UPNSuffix": ...}):
# their field names are too generic for column rules ('Name'), so map them per entity type.
_ACCOUNT = {"name": "USER", "accountname": "USER", "fullname": "USER", "displayname": "USER",
            "upnsuffix": "DOMAIN", "ntdomain": "DOMAIN", "dnsdomain": "DOMAIN", "aaduserid": "USERID",
            "objectguid": "USERID", "puid": "USERID", "sid": "SID", "userprincipalname": "EMAIL",
            "upn": "EMAIL", "aadtenantid": "TENANTID", "email": "EMAIL"}
_MAILBOX = {"mailboxprimaryaddress": "EMAIL", "displayname": "USER", "upn": "EMAIL", "aadid": "USERID",
            "externaldirectoryobjectid": "USERID", "rawname": "USER"}
ENTITY_FIELDS = {
    "account": _ACCOUNT,
    "host": {"hostname": "HOST", "netbiosname": "HOST", "fqdn": "HOST", "dnsdomain": "DOMAIN",
             "ntdomain": "DOMAIN", "omsagentid": "HOSTID", "mdatpdeviceid": "HOSTID", "deviceid": "HOSTID",
             "aaddeviceid": "HOSTID", "azureid": None},
    "mailbox": _MAILBOX, "mailbox-configuration": _MAILBOX,
    "mailmessage": {"recipient": "EMAIL", "sender": "EMAIL", "p1sender": "EMAIL", "p2sender": "EMAIL",
                    "senderdisplayname": "USER", "p1senderdisplayname": "USER",
                    "p2senderdisplayname": "USER", "recipientemailaddress": "EMAIL"},
    "security-group": {"sid": "SID", "objectguid": "USERID"},
    "cloud-logon-session": {"userprincipalname": "EMAIL"},
}

def json_field_category(parent, key, path=()):
    """Category for parent[key]: entity-type aware for Sentinel entities, else by key name/path."""
    if not isinstance(key, str):
        return None
    t = parent.get("Type") or parent.get("type") if isinstance(parent, dict) else None
    if isinstance(t, str):
        m = ENTITY_FIELDS.get(t.lower())
        if m is not None and key.lower() in m:
            return m[key.lower()]
    return column_category(key, path)

# Public AWS service endpoints / principals ('ec2.amazonaws.com', 'AWS Internal') in host-like
# fields are not identifying: they go through the free-text rules instead of becoming HOST_x.
AWS_PUBLIC_RX = re.compile(r"(?i)(?:[a-z0-9-]+\.)*amazonaws\.com|aws internal")
DASHED_IP = r"(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)-){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)"

def resolve_category(cat, value):
    """ENTITY columns hold either a UPN or a host name; USER columns sometimes hold UPNs;
    host columns sometimes hold IPs (-> the same IP token as in free text)."""
    v = value.strip()
    if cat == "ENTITY":
        cat = "EMAIL" if "@" in v else "HOST"
    if cat in ("USER", "EMAIL", "USERID") and "@" in v:
        return "EMAIL"
    if cat == "USERID" and re.fullmatch(r"\d{12}", v):          # AWS accountId in raw CloudTrail JSON
        return "AWSACCOUNT"
    if cat == "HOST":
        try:
            return "IPV4" if ipaddress.ip_address(v).version == 4 else "IPV6"
        except ValueError:
            pass
        if AWS_PUBLIC_RX.fullmatch(v) and not re.search(DASHED_IP, v):
            return None
    return cat

def registrable_label(domain):
    """'corp.acmeholdings.co.in' -> 'acmeholdings'."""
    labels = [l for l in domain.lower().strip(".").split(".") if l]
    if len(labels) < 2:
        return labels[0] if labels else ""
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in {"co", "com", "org", "net", "gov", "ac", "edu"}:
        return labels[-3]
    return labels[-2]

_COLUMN_RX = [(cat, re.compile(rf"(?:{rx})")) for cat, rx in COLUMN_RULES]
COLUMN_OVERRIDES = {}      # norm header -> category or None (keep); filled from --id-columns/--keep-columns
_COL_CACHE = {}

def _rule_category(n):
    return next((c for c, rx in _COLUMN_RX if rx.fullmatch(n)), None)

def column_category(header, path=()):
    """header: a column name or JSON key; path: the enclosing JSON keys (or the cell's column).
    Dotted names ('_source.agent.name') are split into path segments."""
    if not header:
        return None
    ck = (header, path)
    if ck in _COL_CACHE:
        return _COL_CACHE[ck]
    n = norm_header(header)
    if n in COLUMN_OVERRIDES:
        cat = COLUMN_OVERRIDES[n]
    else:
        segs = [s for p in (*path, header) for s in str(p).split(".")] if " " not in header.strip() \
            else [s for p in path for s in str(p).split(".")] + [header]
        segs = [re.sub(r"\[\d+\]$", "", s).lower() for s in segs]
        segs = [s for s in segs if s and not s.isdigit()]     # 'networkInterfaces.0.publicIp'
        cat = _rule_category(n)
        for i in range(len(segs)):
            suffix = ".".join(segs[i:])
            if suffix in FIELD_PATHS:
                cat = FIELD_PATHS[suffix]
                break
        else:
            if cat is None and len(segs) > 1 and "." in header:
                cat = _rule_category(norm_header(header.rsplit(".", 1)[1]))
    _COL_CACHE[ck] = cat
    return cat

# ---------- lexicon: known identifiers, replaced wherever they appear in free text ----------
STOP_TERMS = {"unassigned", "none", "null", "n/a", "na", "nil", "-", "--", "unknown", "system", "admin",
              "administrator", "automation for jira", "jira", "service desk", "internal", "test", "default",
              "true", "false", "yes", "no", "high", "low", "medium", "critical", "open", "closed",
              "root", "nobody", "ec2-user", "ubuntu", "workgroup"}
CORP_SUFFIX = re.compile(r"[\s,.]+(private|pvt\.?|ltd\.?|limited|inc\.?|incorporated|corp\.?|corporation|"
                         r"llc|l\.l\.c\.|llp|plc|gmbh|ag|sa|bv|co\.?|company|group|holdings?|"
                         r"technologies|technology|tech|solutions|services|systems|india|global)\.?$", re.I)

def tenant_core(v):
    """'Acme Holdings Pvt Ltd' -> 'Acme Holdings'."""
    core = v
    while CORP_SUFFIX.search(core):
        core = CORP_SUFFIX.sub("", core).strip()
    return core

class Lexicon:
    """Values seen in identity columns (assignees, tenants, issue keys, account ids ...)
    plus their obvious variants, so 'Acme Holdings Pvt Ltd' in the Tenant column and
    '[Acme] ...' in the Summary get the same token."""

    def __init__(self):
        self.terms = {}            # lowercase term -> (category, canonical value)
        self.names = {}            # name part -> set of full names (for unique first/last names)
        self.key_prefixes = set()  # Jira project keys, e.g. MSSOC
        self.domains = set()       # internal domains (UPNSuffix, DnsDomain, --domains ...)
        self.email_domains = set() # domains seen in internal mailbox / UPN values
        self.tenants = set()       # tenant names (their squashed form marks internal mail domains)
        self.counts = {}
        self.rx = None

    def _put(self, term, cat, canon, weak=False):
        """weak = a derived single-word variant (first name, tenant short name): only
        matched when written like a name (Capitalised or ALL CAPS), so a tenant called
        'Global Bank' doesn't wipe out every 'global' in the text."""
        t = term.strip()
        if len(t) < 3 or t.lower() in STOP_TERMS or (t.isdigit() and cat != "AWSACCOUNT"):
            return
        if weak and " " in t:
            weak = False
        old = self.terms.get(t.lower())
        # a value that is a tenant somewhere (S1 account_name) stays the tenant under 'accountName'
        if old is None or (old[2] and not weak) or (cat == "TENANT" and old[0] == "USER" and not weak):
            self.terms[t.lower()] = (cat, canon, weak)

    def add(self, cat, value):
        v = (value or "").strip()
        if not v or v.lower() in STOP_TERMS or len(v) > 200:
            return
        if cat == "ISSUEKEY":
            m = re.fullmatch(r"([A-Za-z][A-Za-z0-9_]+)-(\d+)", v)
            if m:
                self.key_prefixes.add(m.group(1).upper())
            self.counts[cat] = self.counts.get(cat, 0) + 1
            return
        cat = resolve_category(cat, v)
        if cat == "EMAIL" and "@" in v and not EMAIL_RX.fullmatch(v):
            for e in EMAIL_RX.findall(v):      # 'a@x.com; b@x.com', 'Doe, John <john@x.com>'
                self.add("EMAIL", e)
            for _, rx in DISPLAY_NAME_RULES:
                for name in rx.findall(v):
                    self.add("USER", " ".join(reversed(name.split(", "))) if ", " in name else name)
            return
        if cat in COLUMN_ONLY or (v.isdigit() and cat != "AWSACCOUNT"):
            return                          # bare numbers in prose are too ambiguous to chase
        if cat in ("USER", "TENANT", "USERID", "TENANTID", "EMAIL", "HOST", "HOSTID", "SUBSCRIPTIONID",
                   "RG", "WORKSPACE", "DOMAIN", "SID", "TERM", "AWSACCOUNT", "BUCKET"):
            before = len(self.terms)
            if cat == "DOMAIN":
                self.add_domain(v)
            elif cat == "EMAIL":
                self._put(v, cat, v)
                local, _, dom = v.partition("@")
                if re.fullmatch(r"[A-Za-z][\w'-]*[._][\w.'-]+", local):     # 'priya.sharma' -> same as account Name
                    self._put(local, "USER", local)
                self.email_domains.add(dom.lower())
            else:
                self._put(v, cat, v)
            if cat == "USER" and re.fullmatch(r"[A-Za-z][A-Za-z.'-]+(\s+[A-Za-z][A-Za-z.'-]+){1,3}", v):
                for part in v.split():
                    part = part.strip(".")
                    if len(part) >= 4:
                        self.names.setdefault(part.lower(), set()).add(v)
                self._put(" ".join(reversed(v.split())), cat, v)          # 'Sharma Priya'
                if len(v.split()) == 2:
                    self._put(", ".join(reversed(v.split())), cat, v)     # 'Sharma, Priya'
            if cat == "TENANT":
                core = tenant_core(v)
                self.tenants.add(v)
                self._put(core, cat, v, weak=True)
                for variant in {core.replace(" ", ""), core.replace(" ", "-"),
                                core.replace(" ", "_"), v.replace(" ", "")}:
                    if variant != core:
                        self._put(variant, cat, v)                         # 'AcmeHoldings', 'acme-holdings'
                first = core.split()[0] if core.split() else ""
                if len(first) >= 4 and first.lower() not in STOP_TERMS:
                    self._put(first, cat, v, weak=True)                   # 'Acme' for 'Acme Holdings'
            if len(self.terms) > before:
                self.counts[cat] = self.counts.get(cat, 0) + 1

    def add_domain(self, d):
        d = d.strip().strip(".").lower()
        if "." not in d and not re.fullmatch(r"[a-z0-9-]{3,}", d):
            return
        self.domains.add(d)
        self._put(d, "DOMAIN", d)
        lab = registrable_label(d) if "." in d else d
        if len(lab) >= 3 and lab not in STOP_TERMS:
            # 'acmeholdings' also covers ACMEHOLDINGS\user, acmeholdings.onmicrosoft.com, acmeholdings[.]com
            self._put(lab, "DOMAIN", lab, weak=len(lab) < 6)
        self.counts["DOMAIN"] = self.counts.get("DOMAIN", 0) + 1

    def add_term(self, term, cat="TERM"):
        self._put(term, cat.upper(), term.strip())
        self.counts[cat.upper()] = self.counts.get(cat.upper(), 0) + 1

    def compile(self):
        # domains of internal mailboxes count as internal when they share the registrable
        # label with a known internal domain (attacker look-alike domains stay as IOCs)
        known = {registrable_label(d) for d in self.domains}
        known |= {re.sub(r"[\W_]+", "", x).lower() for t in self.tenants for x in (t, tenant_core(t))}
        for dom in self.email_domains:
            if registrable_label(dom) in known:
                self.add_domain(dom)
        for part, fulls in self.names.items():
            if part in self.terms or part in STOP_TERMS or \
                    any(self.terms.get(f.lower(), ("",))[0] == "TENANT" for f in fulls):
                continue
            if len(fulls) == 1:                 # unique first/last name -> same token as the person
                self.terms[part] = ("USER", next(iter(fulls)), True)
            else:                               # shared part: still hide it, own token
                self.terms[part] = ("NAME", part, True)
        pieces = sorted(self.terms, key=len, reverse=True)
        alts = [re.escape(t) for t in pieces]
        if self.key_prefixes:
            alts.insert(0, rf"(?:{'|'.join(map(re.escape, sorted(self.key_prefixes)))})-\d+")
        self.rx = (re.compile(rf"(?<![^\W_])(?<![@.-])(?:{'|'.join(alts)})(?![^\W_])(?!-)", re.I)
                   if alts else None)
        return self

    def apply(self, text):
        if not self.rx or not text:
            return text
        def sub(m):
            t = m.group(0)
            if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]+-\d+", t) and t.split("-")[0].upper() in self.key_prefixes:
                return pseudo("ISSUEKEY", t.upper())
            cat, canon, weak = self.terms.get(t.lower(), (None, None, False))
            if weak and not (t[:1].isupper()):
                return t                        # 'global' in prose is not the tenant 'Global'
            return pseudo(cat, canon) if cat else t
        return self.rx.sub(sub, text)

    def summary(self):
        parts = [f"{k} {v}" for k, v in sorted(self.counts.items())]
        if self.key_prefixes:
            parts.append("issue-key prefixes " + ",".join(sorted(self.key_prefixes)))
        return f"lexicon: {len(self.terms):,} terms ({'; '.join(parts) or 'none'})"

# ---------- regex rules (order matters: specific before generic) ----------
AWS_RES_ID = (r"\b(?:i|sg|sgr|vpc|subnet|eni|vol|snap|ami|igw|nat|rtb|acl|eipalloc|eipassoc|lt|vpce|pcx|tgw|"
              r"tgw-attach)-[0-9a-f]{8,17}\b")
AWS_KEEP_SEGS = {"", "*", "aws-service-role", "service-role", "aws-reserved"}

def _arn_sub(m):
    """arn:aws:iam::123456789012:assumed-role/AcmeAdmin/priya -> account and names tokenized,
    service / region / resource type kept. AWS-managed ARNs (account 'aws') stay as they are."""
    prefix, service, acct, res = m.group(1), m.group(2), m.group(3), m.group(4)
    if acct == "aws":
        return m.group(0)
    if acct and not TOKEN_RX.fullmatch(acct):
        acct = pseudo("AWSACCOUNT", acct)
    parts = re.split(r"([/:])", res)
    typ = None if service == "s3" else parts[0]
    names = [i for i in range(0 if typ is None else 2, len(parts), 2)]
    for i in names:
        seg = parts[i]
        if seg in AWS_KEEP_SEGS or seg in MAPPING or TOKEN_RX.fullmatch(seg):
            continue
        if service == "s3" and i == 0:
            cat = "BUCKET"
        elif re.fullmatch(AWS_RES_ID, seg):
            cat = "AWSRES"
        elif typ == "user" or (typ == "assumed-role" and i == names[-1] and len(names) > 1):
            cat = resolve_category("USER", seg)               # same token as userName / e-mail columns
        else:
            cat = "AWSRES"
        parts[i] = pseudo(cat, seg)
    return f"{prefix}{acct or ''}:{''.join(parts)}"

# An address starts after a non-address character or after a JSON escape (\n, \", \u003c) in
# text that is still JSON-encoded (cells cut off at Excel's limit): '\njohn@x' is 'john@x'.
EMAIL_START = r"(?:(?<![\w.+'%\\-])|(?<=\\[nrt\"/])|(?<=\\u[0-9a-fA-F]{4}))"
EMAIL_RX = re.compile(rf"{EMAIL_START}[\w.+'%-]+@[\w-]+(?:\.[\w-]+)+\b")
# Display names in front of an address: '"Doe, John" <john@x.com>', 'To: John Doe <john@x.com>'
_ADDR_AHEAD = r"\s*(?:<|&lt;|\\u003[cC])(?=[\w.+'%-]+@)"
DISPLAY_NAME_RULES = [
    ("USER", re.compile(rf'\\?"([^"\\\r\n<>@]{{1,80}}?)\\?"{_ADDR_AHEAD}')),
    ("USER", re.compile(rf"(?:(?<![\w.'-])|(?<=\\[nrt]))([A-Z][\w.'-]*(?:,? [A-Z][\w.'-]*){{0,3}}){_ADDR_AHEAD}")),
]

def build_rules(domains):
    rules = [
        ("SECRET", re.compile(r"\beyJ[\w-]{10,}\.[\w-]{10,}\.[\w-]{10,}\b")),             # JWT
        ("SECRET", re.compile(r"(?i)\b(?:password|passwd|pwd|secret|token|apikey|api_key|sig)=([^&\s\"']+)")),
        # defanged / URL-encoded: john%40acme.com, john[@]acme[.]com, john (at) acme (dot) com
        ("EMAIL_OBF", re.compile(rf"(?i){EMAIL_START}([\w.+'-]+)\s?(?:%40|\[@\]|\(@\)|\[at\]|\(at\)|\{{at\}}|"
                                 r"&#64;|&#x40;|\\u0040|\\x40|＠)\s?"
                                 r"([\w-]+(?:\s?(?:\.|\[\.\]|\(\.\)|\[dot\]|\(dot\)|%2e)\s?[\w-]+)+)\b")),
        ("EMAIL", EMAIL_RX),
        # Azure resource paths and portal links
        ("SUBSCRIPTIONID", re.compile(r"(?i)(?:/subscriptions/|subscriptionId[/=])"
                                      r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})")),
        ("RG", re.compile(r"(?i)(?:/resourceGroups?/|resourceGroup[/=])([^/\s\"'?#&\\]+)")),
        ("WORKSPACE", re.compile(r"(?i)/workspaces/([^/\s\"'?#&\\]+)")),
        ("HOST", re.compile(r"(?i)/(?:virtualMachines|machines|computers)/([^/\s\"'?#&\\]+)")),
        # AWS: ARNs (account + resource names, structure kept), account ids in S3 log paths,
        # access key ids, resource ids (i-, sg-, sgr-, vpc- ...)
        ("ARN", re.compile(r"\b(arn:aws[\w-]*:([\w-]*):[\w-]*:)(\d{12}|aws|AWSACCOUNT_[0-9a-f]{8})?:"
                           r"([^\s\"',;<>\[\]{}()]+)")),
        ("AWSACCOUNT", re.compile(r"(?i)AWSLogs/(?:o-[a-z0-9]+/)?(\d{12})(?=/)")),
        ("AWSACCOUNT", re.compile(r"(?<![\w-])(\d{12})(?=_(?:CloudTrail|vpcflowlogs|elasticloadbalancing|"
                                  r"GuardDuty|Config|CloudTrail-Digest)[_-])")),
        ("AWSKEY", re.compile(r"\b(?:AKIA|ASIA|AIDA|AROA|AGPA|ANPA|ANVA|AIPA|APKA|ABIA|ACCA)[A-Z0-9]{16}\b")),
        ("AWSRES", re.compile(AWS_RES_ID)),
        ("DOMAIN", re.compile(r"(?i)\b([\w-]+)\.onmicrosoft\.com\b")),
        ("DOMAIN", re.compile(r"(?i)\bDC=([\w-]+)")),
        ("SID", re.compile(r"\bS-1-5-21-\d+-\d+-\d+-\d+\b")),
        ("GUID", re.compile(r"(?<![0-9A-Fa-f-])[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?![0-9A-Fa-f-])")),
        ("MAC", re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")),
        # host names that embed an IP: ip-10-0-3-184, ip-10-0-3-184.ec2.internal, ec2-54-1-2-3.compute-1...
        ("HOST", re.compile(rf"(?i)\b[a-z][a-z0-9]{{0,15}}-{DASHED_IP}(?:\.[a-z0-9-]+)*\b")),
        ("IPV4", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")),
        # also compressed forms (2600:1f18::1); candidates are validated with ipaddress
        ("IPV6", re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?![\w:])")),
        ("USER", re.compile(r"(?i)(?<=[\\/]users[\\/])[^\\/\s\"']+")),                     # C:\Users\x, /Users/x
        ("USER", re.compile(r"(?i)(?<=/home/)[^/\s\"']+")),
        ("USER", re.compile(r"\b[A-Z][A-Z0-9-]{1,14}\\([A-Za-z0-9._$-]{2,})\b")),         # DOMAIN\user
        *DISPLAY_NAME_RULES,
    ]
    if domains:
        d = "|".join(re.escape(x) for x in domains)
        rules.append(("HOST", re.compile(rf"(?i)\b[\w-]+(?:\.[\w-]+)*\.(?:{d})\b")))
    return rules

def _deobf_email(m):
    if m.group(0) in MAPPING:
        return m.group(0)
    local, dom = m.group(1), m.group(2)
    dom = re.sub(r"(?i)\s?(?:\[\.\]|\(\.\)|\[dot\]|\(dot\)|%2e|\.)\s?", ".", dom)
    return pseudo("EMAIL", f"{local}@{dom}")

def apply_rules(text, rules):
    for cat, rx in rules:
        if cat == "EMAIL_OBF":
            text = rx.sub(_deobf_email, text)
            continue
        if cat == "ARN":
            text = rx.sub(_arn_sub, text)
            continue
        def sub(m):
            if m.lastindex:  # replace only the captured group
                g = m.group(1)
                if g in MAPPING or TOKEN_RX.fullmatch(g):      # already a token: never re-anonymize
                    return m.group(0)
                return m.group(0).replace(g, pseudo(cat, g))
            v = m.group(0)
            if v in MAPPING or TOKEN_RX.fullmatch(v):
                return v
            if cat == "HOST" and v.split(".")[0] in MAPPING:   # 'HOST_ab12cd34.corp.local' -> keep the token
                return v.split(".")[0]
            if cat in ("IPV4", "IPV6"):
                try:
                    ipaddress.ip_address(v)
                except ValueError:
                    return v
            return pseudo(cat, v)
        text = rx.sub(sub, text)
    return text

# ---------- NER for free text ----------
DEFAULT_NER_MODEL = "fastino/gliner2-privacy-filter-PII-multi"   # GLiNER2-PII, Apache-2.0
# Native labels of GLiNER2-PII (it was trained on these exact snake_case names).
# Emails, IPs, GUIDs etc. are left to the regex rules, which are exact.
LABEL_CAT = {
    "person": "PERSON", "full_name": "PERSON", "first_name": "PERSON", "last_name": "PERSON",
    "street_address": "ADDRESS", "address": "ADDRESS", "phone_number": "PHONE",
    "username": "USER", "account_id": "ACCT", "sensitive_account_id": "ACCT",
    "national_id_number": "ID", "government_id": "ID", "passport_number": "ID",
    "bank_account": "ACCT", "card_number": "CARD",
    "password": "SECRET", "api_key": "SECRET", "access_token": "SECRET", "secret": "SECRET",
}
NER_LABELS = list(LABEL_CAT)
# the model card notes it over-predicts names -> stricter threshold for name labels
NAME_LABELS = {"person", "full_name", "first_name", "last_name"}
# "key": "value" pairs (also \"key\": \"value\" one level down) in JSON that doesn't parse,
# e.g. alert payloads cut off at Excel's 32,767-character cell limit. Values with escapes are
# left to the free-text rules.
KV_RX = re.compile(r'(\\?)"([A-Za-z_@$][\w.@$-]{0,63})\1"\s*:\s*\1"([^"\\]{1,500})\1"')
TOKEN_RX = re.compile(r"\b(?:[A-Z]+_[0-9a-f]{8}|user_[0-9a-f]{8}@example\.com|TKT-\d{7})\b")

def prefetch_model(model_name):
    """Download the NER weights into the Hugging Face cache (no data is sent)."""
    if os.environ.get("HF_HUB_OFFLINE") == "1":
        sys.exit("Unset HF_HUB_OFFLINE for the one-time download:  unset HF_HUB_OFFLINE")
    from huggingface_hub import snapshot_download
    path = snapshot_download(model_name)
    log(f"model cached at {path}\nfrom now on you can run with HF_HUB_OFFLINE=1", style="green")

def pick_device(want="auto"):
    """'auto': CUDA GPU (cloud box), else CPU. Apple GPU ('mps') is opt-in until its
    NER output has been checked against CPU on real hardware."""
    if want != "auto":
        return want
    import torch
    return "cuda" if torch.cuda.is_available() else "cpu"

class NER:
    lock = threading.Lock()   # one forward pass at a time: the tokenizer isn't thread-safe

    def __init__(self, model_name, threshold, name_threshold, device="auto"):
        self.hits = 0
        err = None
        os.environ.setdefault("PYTORCH_ENABLE_MPS_FALLBACK", "1")   # ops MPS lacks run on CPU
        with CONSOLE.status(f"loading NER model {model_name} ...", spinner="dots"):
            from gliner2 import GLiNER2
            try:
                device = pick_device(device)
                self.model = GLiNER2.from_pretrained(model_name, map_location=device)
            except Exception as e:  # missing from cache / offline / wrong id / no such device
                err = e
        if err:
            sys.exit(f"Could not load NER model '{model_name}': {type(err).__name__}.\n"
                     f"Download it once (model weights only, none of your data is sent):\n"
                     f"  unset HF_HUB_OFFLINE && uv run {Path(sys.argv[0]).name} --prefetch\n"
                     f"or pass --model /path/to/local/model_dir, or use --no-ner.")
        log(f"NER model: {model_name} on {device}")
        self.threshold, self.name_threshold = threshold, max(threshold, name_threshold)

    def __call__(self, text):
        if looks_like_blob(text):
            return text
        with self.lock:
            out = self.model.extract_entities(text, NER_LABELS, threshold=self.threshold,
                                              include_confidence=True, max_len=384)
        ents = out.get("entities", out) if isinstance(out, dict) else {}
        found = []
        for label, items in ents.items():
            floor = self.name_threshold if label in NAME_LABELS else self.threshold
            for it in items or []:
                span, conf = (it.get("text"), it.get("confidence", 1.0)) if isinstance(it, dict) else (it, 1.0)
                if (span and len(span) > 1 and conf >= floor and span in text
                        and not TOKEN_RX.fullmatch(span) and span not in MAPPING):
                    found.append((LABEL_CAT.get(label, "PII"), span))
        with self.lock:
            self.hits += len(found)
        for cat, span in sorted(found, key=lambda x: -len(x[1])):  # longest first
            text = text.replace(span, pseudo(cat, span))
        return text

def chunks(text, size=1000):
    """Split text into pieces of at most ~size chars, preferring line breaks, then
    whitespace. Hard limit matters: the NER encoder's cost grows with the square of
    the input length, so one 20k-char single-line cell used to stall a whole run."""
    parts, buf = [], ""
    for line in text.splitlines(keepends=True):
        while len(line) > size:                       # very long single line
            cut = max(line.rfind(" ", 0, size), line.rfind("\t", 0, size))
            cut = cut + 1 if cut > size // 2 else size  # no good space: hard cut
            if buf:
                parts.append(buf); buf = ""
            parts.append(line[:cut]); line = line[cut:]
        if len(buf) + len(line) > size and buf:
            parts.append(buf); buf = ""
        buf += line
    return parts + [buf] if buf else parts

def looks_like_blob(text):
    """base64 / hex / hashes / minified tokens: no prose, so no names for NER to find
    (the regex rules still run on them). Prose has a space every ~5-8 chars."""
    t = text.strip()
    return len(t) >= 60 and t.count(" ") < len(t) / 40

# ---------- optional 2nd pass: local LLM reviewer (LM Studio / any OpenAI-compatible server) ----------
REVIEW_SYSTEM = """You audit security-operations text that has ALREADY been anonymized.
Placeholders look like USER_1a2b3c4d, TENANT_..., HOST_..., PERSON_..., SID_..., SECRET_...,
ticket keys like TKT-1234567, user_1a2b3c4d@example.com, IPs in 198.18.0.0/15,
2001:db8:: addresses and random GUIDs.
Placeholders are NOT leaks.

Report every remaining value that could identify a real person or the organisation:
person names, usernames/logins, email addresses, phone numbers, street addresses,
internal hostnames or domains, company/customer/employee names, employee or badge IDs,
tenant/account identifiers, credentials, API keys, tokens.

Do NOT report: public malware/threat names, public vendor or product names
(Microsoft, Azure, Okta, CrowdStrike...), public external domains/IPs that are
indicators of compromise, timestamps, event IDs, ticket keys, file hashes, process names.

Copy each leak EXACTLY as it appears in the text (same characters and case).
If nothing leaks return {"leaks": []}."""

REVIEW_SCHEMA = {
    "type": "object",
    "properties": {"leaks": {"type": "array", "items": {
        "type": "object",
        "properties": {"text": {"type": "string"}, "type": {"type": "string"}},
        "required": ["text", "type"]}}},
    "required": ["leaks"],
}

class Reviewer:
    LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}

    def __init__(self, url, model=None, apply=False, report=None, allow_remote=False,
                 min_len=20, timeout=180):
        host = urlparse(url).hostname or ""
        if host not in self.LOCAL_HOSTS and not allow_remote:
            sys.exit(f"--review-url host '{host}' is not local. If it is your PRIVATE "
                     "endpoint, re-run with --allow-remote-review.")
        self.url, self.apply, self.min_len, self.timeout = url.rstrip("/"), apply, min_len, timeout
        self.model = model or self._loaded_model()
        if report:
            report.parent.mkdir(parents=True, exist_ok=True)
        self.report = report.open("w", encoding="utf-8") if report else None
        self.cache, self.calls, self.flagged, self.file = {}, 0, 0, ""
        self.lock = threading.Lock()         # several requests in flight (Anonymizer.workers)
        self.on_call = lambda: None          # progress hook, set by the UI
        log(f"review model: {self.model} at {self.url} "
            f"({'apply' if apply else 'dry run, report only'})")

    def _http(self, path, body=None):
        req = urllib.request.Request(
            self.url + path, data=json.dumps(body).encode() if body else None,
            headers={"Content-Type": "application/json", "Authorization": "Bearer lm-studio"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return json.loads(r.read())
        except urllib.error.URLError as e:
            sys.exit(f"review server unreachable at {self.url}: {e}. "
                     "Start it in LM Studio (Developer tab) or with `lms server start`.")

    def _loaded_model(self):
        ids = [m["id"] for m in self._http("/models").get("data", [])
               if "embed" not in m["id"].lower()]
        if not ids:
            sys.exit("No model loaded in LM Studio. Run `lms load <model>` or pass --review-model.")
        return ids[0]

    def _ask(self, text):
        body = {
            "model": self.model, "temperature": 0, "max_tokens": 2048, "stream": False,
            "messages": [{"role": "system", "content": REVIEW_SYSTEM},
                         {"role": "user", "content": f"TEXT:\n<<<\n{text}\n>>>"}],
            "response_format": {"type": "json_schema",
                                "json_schema": {"name": "leaks", "strict": True, "schema": REVIEW_SCHEMA}},
        }
        content = self._http("/chat/completions", body)["choices"][0]["message"].get("content") or ""
        content = re.sub(r"(?s)<think>.*?</think>", "", content)  # reasoning models
        m = re.search(r"(?s)\{.*\}", content)
        try:
            return json.loads(m.group(0)).get("leaks", []) if m else []
        except ValueError:
            return []

    def __call__(self, text):
        if len(text) < self.min_len or not re.search(r"[A-Za-z]{3,}", text):
            return text
        if text in self.cache:
            return self.cache[text]
        out = text
        for chunk in chunks(text, 2000):
            with self.lock:
                self.calls += 1
            leaks = self._ask(chunk)
            self.on_call()
            for leak in leaks:
                span, kind = str(leak.get("text", "")).strip(), str(leak.get("type", "PII"))
                # accept only real, non-placeholder spans: the LLM can flag, never invent
                if len(span) < 3 or span not in out or span in MAPPING or TOKEN_RX.fullmatch(span):
                    continue
                with self.lock:
                    self.flagged += 1
                    if self.report:
                        self.report.write(json.dumps({"file": self.file, "type": kind, "text": span,
                                                      "applied": self.apply}, ensure_ascii=False) + "\n")
                if self.apply:
                    cat = re.sub(r"[^A-Z]", "", kind.upper())[:12] or "PII"
                    out = out.replace(span, pseudo(cat, span))
        self.cache[text] = out
        return out

    def close(self):
        if self.report:
            self.report.close()
        log(f"review: {self.calls} LLM calls, {self.flagged} spans flagged"
            f"{' and pseudonymized' if self.apply else ' (dry run, not applied)'}"
            f"{f' -> {self.report.name}' if self.report else ''}",
            style="yellow" if self.flagged else "green")

def ordered_map(fn, items, workers=1):
    """fn(item) for each item, yielded in input order. With workers > 1 the calls
    run in a thread pool, at most 2*workers items ahead of the consumer, so the
    LLM reviewer has several requests in flight while files still stream (the
    work is mostly waiting on HTTP; NER takes its lock)."""
    if workers <= 1:
        yield from map(fn, items)
        return
    from collections import deque
    from concurrent.futures import ThreadPoolExecutor
    pool, pending = ThreadPoolExecutor(workers, thread_name_prefix="scrub"), deque()
    try:
        for it in items:
            pending.append(pool.submit(fn, it))
            if len(pending) >= 2 * workers:
                yield pending.popleft().result()
        while pending:
            yield pending.popleft().result()
    finally:
        pool.shutdown(wait=True, cancel_futures=True)

# ---------- recursive walker ----------
MEMO_MAX_LEN, MEMO_SIZE = 512, 50_000   # scrub_str cache: at most ~60 MB

class Anonymizer:
    def __init__(self, rules, ner=None, ner_min_len=25, reviewer=None, lexicon=None, workers=1):
        self.rules, self.ner, self.ner_min_len = rules, ner, ner_min_len
        self.reviewer, self.lexicon = reviewer, lexicon or Lexicon().compile()
        self.workers = workers   # records scrubbed concurrently (only pays off with the reviewer)
        self.email_rules = [r for r in rules if r[0] in ("EMAIL", "EMAIL_OBF")]
        self.other_rules = [r for r in rules if r[0] not in ("EMAIL", "EMAIL_OBF")]
        self.memo = {}   # short values repeat a lot (status, tenant, alert title): scrub once

    def map(self, fn, items):
        return ordered_map(fn, items, self.workers)

    def pseudo_field(self, cat, s):
        if cat == "ISSUEKEY":
            return self.lexicon.apply(s) if " " in s.strip() else pseudo(cat, s.upper())
        if cat == "DOMAIN":
            return pseudo("DOMAIN", s.strip().lower())
        cat = resolve_category(cat, s)
        if cat == "USER" and self.lexicon.terms.get(s.strip().lower(), ("",))[0] == "TENANT":
            return pseudo("TENANT", self.lexicon.terms[s.strip().lower()][1])
        return pseudo(cat, s)

    def scrub_key(self, k):
        """JSON keys can carry PII too ({"rahul@acme.com": ...}); no NER, rules + lexicon only."""
        if not isinstance(k, str) or len(k) < 3 or k.startswith("$"):
            return k
        return apply_rules(self.lexicon.apply(apply_rules(k, self.email_rules)), self.other_rules)

    def scrub_str(self, s, key=None, cat=None, path=()):
        if len(s) > MEMO_MAX_LEN:
            return self._scrub_str(s, key, cat, path)
        k = (s, key, cat, path)
        out = self.memo.get(k)
        if out is None:
            if len(self.memo) >= MEMO_SIZE:
                self.memo.clear()
            out = self.memo[k] = self._scrub_str(s, key, cat, path)
        return out

    def _scrub_str(self, s, key=None, cat=None, path=()):
        t = s.strip()
        if t[:1] in "{[" and len(t) > 1:
            try:
                inner = path or ((key,) if isinstance(key, str) else ())
                return json.dumps(self.walk(json.loads(t), path=inner), ensure_ascii=False,
                                  separators=(",", ":"))
            except ValueError:
                s = KV_RX.sub(self._kv_sub, s)        # cut-off JSON: still honour "key": "value" fields
        cat = column_category(key) if cat is None else cat
        rc = resolve_category(cat, t) if cat and t else None   # None: public AWS endpoint -> free text
        if rc and not (rc == "EMAIL" and "@" in t and not EMAIL_RX.fullmatch(t)):
            return self.pseudo_field(cat, s)          # (several addresses / display names: free text)
        s = apply_rules(s, self.email_rules)  # whole e-mail addresses first (also defanged / %40)
        s = self.lexicon.apply(s)             # known names / tenants / keys -> same tokens as their columns
        s = apply_rules(s, self.other_rules)
        if self.ner and len(s) >= self.ner_min_len and re.search(r"[A-Za-z]{3,} [A-Za-z]", s):
            s = "".join(self.ner(c) for c in chunks(s))
        if self.reviewer:
            s = self.reviewer(s)
        return s

    def _kv_sub(self, m):
        k, v = m.group(2), m.group(3)
        known = self.lexicon.terms.get(v.lower())     # same token as the parsed JSON / columns gave it
        if known and not known[2]:
            return m.group(0).replace(v, pseudo(known[0], known[1]))
        if not column_category(k):
            return m.group(0)
        return m.group(0).replace(v, self.scrub_str(v, k))

    def walk(self, obj, key=None, cat=None, path=()):
        """path: keys from the document root ('_source', 'agent'), for dotted FIELD_PATHS."""
        if isinstance(obj, dict):
            out = {}
            for k, v in obj.items():
                c = json_field_category(obj, k, path)
                p = (*path, k) if isinstance(k, str) else path
                out[self.scrub_key(k)] = self.walk(v, k, c or "", p)   # "" = known: not an identity field
            return out
        if isinstance(obj, list):
            return [self.walk(v, key, cat, path) for v in obj]
        if isinstance(obj, str):
            return self.scrub_str(obj, key, cat if cat else (None if cat is None else ""), path)
        return obj

# ---------- progress display ----------
NAME_W = 36

def fit(name, w=NAME_W):
    """Fixed-width file name; long names keep their start and their extension."""
    return name.ljust(w) if len(name) <= w else name[: w - 13] + "…" + name[-12:]

class UI:
    """One TOTAL bar + one bar for the file in progress. Finished files are
    printed above the bars as fixed-width summary lines."""

    def __init__(self, n_files, ner=None, reviewer=None, enabled=True):
        from rich.progress import (BarColumn, Progress, TaskProgressColumn,
                                   TextColumn, TimeElapsedColumn, TimeRemainingColumn)
        from rich.table import Column
        self.ner, self.reviewer, self.enabled = ner, reviewer, enabled
        self.progress = Progress(
            TextColumn("{task.description}", markup=False, table_column=Column(width=NAME_W, no_wrap=True)),
            BarColumn(bar_width=28), TaskProgressColumn(),
            TextColumn("{task.fields[count]}", markup=False, justify="right",
                       table_column=Column(justify="right", min_width=11)),
            TextColumn("{task.fields[unit]}", markup=False, table_column=Column(width=7)),
            TimeElapsedColumn(), TextColumn("eta", style="dim"), TimeRemainingColumn(),
            TextColumn("{task.fields[info]}", markup=False, style="cyan"),
            console=CONSOLE, transient=False, disable=not enabled, refresh_per_second=8)
        self.n_files, self.files_done = n_files, 0
        self.total = self.progress.add_task(fit("TOTAL"), total=n_files, unit="files", info="",
                                            count=f"0/{n_files}")
        self.task, self.t0, self.n_ok, self.n_fail = None, 0.0, 0, 0
        if reviewer:
            reviewer.on_call = self.refresh

    def __enter__(self):
        self.progress.start(); return self

    def __exit__(self, *exc):
        self.refresh(); self.progress.stop()

    def _info(self):
        parts = []
        if self.ner:
            parts.append(f"ner {self.ner.hits}")
        if self.reviewer:
            parts.append(f"llm {self.reviewer.calls} · flagged {self.reviewer.flagged}")
        return " · ".join(parts)

    def start(self, name, total, unit, where=None):
        """The bar runs to `total` records, or - for streamed files, whose record count
        isn't known up front - to `total` bytes with where() = bytes read so far.
        The count column always shows records."""
        self.t0 = time.monotonic()
        self.unit, self.count, self.where = unit, 0, where
        self.task = self.progress.add_task(fit(name), total=max(total, 1), unit=unit, count="0",
                                           info=self._info())

    def advance(self, n=1):
        self.count += n
        pos = {"completed": self.where()} if self.where else {"advance": n}
        self.progress.update(self.task, count=f"{self.count:,}", info=self._info(), **pos)

    def refresh(self):
        if self.task is not None:
            self.progress.update(self.task, info=self._info())
        self.progress.update(self.total, info=self._info())

    def _line(self, mark, style, name, detail):
        CONSOLE.print(f"[{style}]{mark}[/] {escape(fit(name))} {escape(detail)}", highlight=False)

    def finish(self, name, note=""):
        el = time.monotonic() - self.t0
        self._close_task()
        self.n_ok += 1
        self._line("✓", "green", name, f"{self.count:>9,} {self.unit:<7} {el:7.1f}s  {note}".rstrip())

    def fail(self, name, why):
        self._close_task()
        self.n_fail += 1
        self._line("✗", "red", name, why)

    def skip(self, name, why):
        self._tick_total()
        self._line("–", "yellow", name, why)

    def _close_task(self):
        if self.task is not None:
            self.progress.remove_task(self.task)
            self.task = None
        self._tick_total()

    def _tick_total(self):
        self.files_done += 1
        self.progress.update(self.total, advance=1, count=f"{self.files_done}/{self.n_files}")

# ---------- delimiter detection ----------
def detect_delimiter(sample, suf):
    """Parse the first ~50 records with each candidate delimiter and keep the one
    that gives a multi-column header and the most rows of the same width.
    (csv.Sniffer is easily fooled by Jira exports whose free-text cells are full
    of commas, semicolons and line breaks.)"""
    default = {".tsv": "\t", ".tab": "\t", ".psv": "|"}.get(suf, ",")
    if suf != ".csv":
        return default
    best, best_score = default, None
    for d in (",", ";", "\t", "|"):
        try:
            rows = list(itertools.islice(csv.reader(io.StringIO(sample, newline=""), delimiter=d), 51))
        except csv.Error:
            continue
        if not rows or len(rows[0]) < 2:
            continue
        body = rows[1:-1] if len(rows) > 2 else rows[1:]          # last one may be cut off
        same = sum(1 for r in body if len(r) == len(rows[0])) / max(len(body), 1)
        score = (round(same, 2), d == default, len(rows[0]))
        if best_score is None or score > best_score:
            best, best_score = d, score
    return best

# ---------- streaming readers: one record in memory, never the whole file ----------
_JSON_WS = re.compile(r"[ \t\n\r]*")

class JsonStream:
    """Pull parser for the outer levels of a JSON document read from a text stream.
    Objects and arrays are entered key by key / element by element; every other
    value (and every array element) is decoded on its own with raw_decode, so a
    multi-GB {"value": [...]} export never has to fit in memory."""

    def __init__(self, fh, chunk=1 << 20):
        self.fh, self.chunk, self.buf, self.pos, self.eof = fh, chunk, "", 0, False
        self.dec = json.JSONDecoder()

    def _more(self):
        # read at least as much as is buffered: a record larger than the chunk is
        # re-decoded O(log size) times instead of once per chunk
        data = self.fh.read(max(self.chunk, len(self.buf) - self.pos))
        self.buf, self.pos, self.eof = self.buf[self.pos:] + data, 0, not data
        return bool(data)

    def peek(self):
        """Next non-blank character, not consumed ('' at the end of the input)."""
        while True:
            self.pos = _JSON_WS.match(self.buf, self.pos).end()
            if self.pos < len(self.buf):
                return self.buf[self.pos]
            if not self._more():
                return ""

    def take(self, ch):
        c = self.peek()
        if c != ch:
            raise ValueError(f"invalid JSON: expected {ch!r}, found {c or 'end of file'!r}")
        self.pos += 1

    def value(self):
        self.peek()
        while True:
            try:
                v, end = self.dec.raw_decode(self.buf, self.pos)
                # a number may go on in the next chunk ('-0.5' + 'e-7'): need 3 chars after it
                if len(self.buf) - end >= 3 or self.eof:
                    self.pos = end
                    return v
            except json.JSONDecodeError as e:
                # a value cut off by the buffer fails at its end (or as an unterminated string)
                if self.eof or (e.pos < len(self.buf) - 8 and not e.msg.startswith("Unterminated")):
                    raise
            self._more()

    def elements(self):
        """Iterate an array; the caller consumes each element (value() or nested)."""
        self.take("[")
        if self.peek() == "]":
            self.pos += 1
            return
        while True:
            yield
            if self._close("]"):
                return

    def keys(self):
        """Iterate an object's keys; the caller consumes each value."""
        self.take("{")
        if self.peek() == "}":
            self.pos += 1
            return
        while True:
            k = self.value()
            self.take(":")
            yield k
            if self._close("}"):
                return

    def _close(self, end):
        c = self.peek()
        if c not in (",", end):
            raise ValueError(f"invalid JSON: expected ',' or {end!r}, found {c or 'end of file'!r}")
        self.pos += 1
        return c == end

    def finish(self):
        if self.peek():
            raise ValueError("invalid JSON: extra data after the document")

def json_dump_at(v, depth):
    """json.dumps(v, indent=2) as it reads nested `depth` levels deep, so streamed
    output is laid out exactly like a whole-document dump."""
    return json.dumps(v, ensure_ascii=False, indent=2).replace("\n", "\n" + "  " * depth)

def is_ndjson(fh, cap=1 << 24):
    """JSON lines saved as .json: the first non-blank line is a complete JSON value
    and more follows. Reads at most a couple of lines, then rewinds."""
    try:
        lines = iter(lambda: fh.readline(cap), "")
        first = next((l for l in lines if l.strip()), "")
        if len(first) >= cap:                      # one huge line: a minified document
            return False
        try:
            json.loads(first)
        except ValueError:
            return False
        return any(l.strip() for l in lines)
    finally:
        fh.seek(0)

CALAMINE_MAX_MB = 1000   # larger books are read by openpyxl read-only: ~10x slower, flat memory

def xlsx_stream(path):
    """Worksheets (incl. hidden ones, not chart sheets) as (title, hidden, rows) for
    streaming; rows are value lists ('' -> None, control characters made safe,
    formulas -> cached values). Empty rows are only passed on when a non-empty row
    follows, so sheets formatted down to row 1,048,576 don't end in blank rows.
    calamine (Rust) parses ~10x faster than openpyxl but holds the sheet being read
    (about its XML size); books above CALAMINE_MAX_MB use openpyxl read-only."""
    if xlsx_sheet_mb(path) <= CALAMINE_MAX_MB:
        from python_calamine import CalamineWorkbook
        book = CalamineWorkbook.from_path(str(path))
        try:
            for m in book.sheets_metadata:
                if str(m.typ).endswith(".WorkSheet"):
                    sheet = book.get_sheet_by_name(m.name)
                    pad = [None] * sheet.start[1] if sheet.start else []  # iter_rows drops empty leading columns
                    rows = (pad + [None if v == "" else XL_ILLEGAL.sub("\ufffd", v) if isinstance(v, str) else v
                                   for v in row] for row in sheet.iter_rows())  # _xHHHH_ already decoded
                    yield m.name, not str(m.visible).endswith(".Visible"), _drop_trailing_empty(rows)
        finally:
            book.close()
        return
    from openpyxl import load_workbook
    book = load_workbook(path, read_only=True, data_only=True)
    try:
        for ws in book.worksheets:
            ws.reset_dimensions()                  # a wrong <dimension> would cut rows off
            rows = ([None if v == "" else xl_safe(v) for v in row] for row in ws.iter_rows(values_only=True))
            yield ws.title, ws.sheet_state != "visible", _drop_trailing_empty(rows)
    finally:
        book.close()

def _drop_trailing_empty(rows):
    gap = 0
    for vals in rows:
        if not _nonempty(vals):
            gap += 1
            continue
        yield from itertools.repeat([], gap)
        gap = 0
        yield vals

def xlsx_est_rows(path):
    """Rows per the sheets' <dimension> tags (near the start of each sheet XML):
    a quick estimate for the progress bar."""
    import zipfile
    n = 0
    try:
        with zipfile.ZipFile(path) as z:
            for i in z.infolist():
                if i.filename.startswith("xl/worksheets/") and i.filename.endswith(".xml"):
                    with z.open(i) as fh:
                        m = re.search(rb'<dimension ref="(?:[A-Z]+\d+:)?[A-Z]+(\d+)"', fh.read(4096))
                    n += int(m.group(1)) if m else 0
    except zipfile.BadZipFile:
        pass
    return n

# ---------- pre-scan: learn identifiers from identity columns of all inputs ----------
def prescan(jobs, lexicon, cancel_ok=True):
    """Collect values of identity columns (assignee, tenant, issue key, account id ...)
    from every input file, so free text in any file can reuse their tokens.
    Returns {file label: [(header, category), ...]} for display."""
    seen_cols = {}

    def take(label, header, values_rows):
        cats = {i: column_category(h) for i, h in enumerate(header)}
        shown = [(h, cats[i]) for i, h in enumerate(header) if cats[i]]
        if shown:
            seen_cols[label] = shown
        for r in values_rows:
            for i, v in enumerate(r):
                if not isinstance(v, str) or not v:
                    continue
                if cats.get(i) and not v.lstrip()[:1] in ("{", "["):
                    lexicon.add(cats[i], v)
                elif v.lstrip()[:1] in ("{", "["):        # JSON inside a cell (Entities, ExtendedProperties ...)
                    walk_str(v, (header[i],) if i < len(header) else ())

    def walk_str(v, path=()):
        try:
            walk(json.loads(v), path)
        except ValueError:                        # cut off: learn its "key": "value" fields
            for m in KV_RX.finditer(v):
                c = column_category(m.group(2))
                if c:
                    lexicon.add(c, m.group(3))

    def walk(obj, path=()):
        if isinstance(obj, dict):
            for k, v in obj.items():
                c = json_field_category(obj, k, path)
                p = (*path, k) if isinstance(k, str) else path
                if c and isinstance(v, str) and not v.lstrip()[:1] in ("{", "["):
                    lexicon.add(c, v)
                elif isinstance(v, str) and v.lstrip()[:1] in ("{", "["):
                    walk_str(v, p)
                elif c and isinstance(v, list):
                    for x in v:
                        if isinstance(x, str):
                            lexicon.add(c, x)
                        else:
                            walk(x, p)
                else:
                    walk(v, p)
        elif isinstance(obj, list):
            for v in obj:
                walk(v, path)

    for f, _dst, label in jobs:
        cur, suf = label, f.suffix.lower()
        try:
            if suf in (".csv", ".tsv", ".tab", ".psv"):
                with f.open("r", encoding="utf-8-sig", errors="replace", newline="") as fh:
                    head = fh.read(262144); fh.seek(0)
                    rd = csv.reader(fh, delimiter=detect_delimiter(head, suf))
                    header = next(rd, [])
                    take(label, header, rd)
            elif suf in (".xlsx", ".xlsm"):
                for title, _hidden, rows in xlsx_stream(f):
                    rows = (r for r in rows if r)
                    header = next(rows, None)
                    if header is not None:
                        take(f"{label} › {title}", ["" if x is None else str(x) for x in header], rows)
            elif suf in (".ndjson", ".jsonl", ".json"):
                with f.open("r", encoding="utf-8-sig", errors="replace", newline="") as fh:
                    if suf != ".json" or is_ndjson(fh):
                        for line in fh:
                            if line.strip():
                                try:
                                    walk(json.loads(line))
                                except ValueError:
                                    pass
                    else:
                        js, rest = JsonStream(fh), {}
                        if js.peek() == "{":            # Azure {"value": [...]}: one record at a time
                            for k in js.keys():
                                if js.peek() == "[":
                                    for _ in js.elements():
                                        walk(js.value(), (k,))
                                else:
                                    rest[k] = js.value()
                            walk(rest)
                        elif js.peek() == "[":
                            for _ in js.elements():
                                walk(js.value())
                        else:
                            walk(js.value())
        except Exception:
            pass                      # the real pass will report a broken file
    return seen_cols

def load_terms(path, lexicon):
    """--terms file: one term per line, optionally 'term,CATEGORY'. '#' = comment."""
    n = 0
    for line in Path(path).read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        term, _, cat = line.rpartition(",") if re.search(r",\s*[A-Za-z]+$", line) else (line, "", "TERM")
        lexicon.add_term(term.strip(), re.sub(r"[^A-Z]", "", cat.upper()) or "TERM")
        n += 1
    return n

# ---------- file handlers ----------
def _nonempty(values):
    return any(v not in (None, "") for v in values)

def _last_row(ws):
    """Last row holding a real value - ignores cells that only carry formatting."""
    rows = [r for (r, _c), cell in ws._cells.items() if cell.value not in (None, "")]
    return max(rows) if rows else 0

def xlsx_sheet_mb(path):
    """Uncompressed size of the sheet XML + shared strings: a good predictor of how
    slow / memory-hungry a full openpyxl load will be (also catches sheets whose
    formatting runs down to row 1,048,576, which the file size alone hides)."""
    import zipfile
    try:
        with zipfile.ZipFile(path) as z:
            return sum(i.file_size for i in z.infolist()
                       if (i.filename.startswith("xl/worksheets/") and i.filename.endswith(".xml"))
                       or i.filename == "xl/sharedStrings.xml") / 1e6
    except zipfile.BadZipFile:
        return 0.0

XL_ILLEGAL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
XL_ESCAPE = re.compile(r"_x([0-9A-Fa-f]{4})_")

def xl_safe(v):
    """Excel stores control characters as _xHHHH_ escapes (CR as _x000D_), which
    openpyxl leaves as they are: decode them, so '10.1.2.3_x000D_' is still an IP
    to the rules. openpyxl refuses control characters in cells, so those become
    U+FFFD before scrubbing and names split by them are still matched."""
    if not isinstance(v, str):
        return v
    if "_x" in v:
        v = XL_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), v)
    return XL_ILLEGAL.sub("\ufffd", v)

def process_xlsx(path, out, anon, ui, full_max_mb):
    """Small books: full-fidelity in-place scrub. Large books (or sheets formatted
    down to row 1,048,576): streaming read + streaming write, values only."""
    data_mb = xlsx_sheet_mb(path)
    if data_mb <= full_max_mb:
        return process_xlsx_full(path, out, anon, ui)
    return process_xlsx_fast(path, out, anon, ui, data_mb)

def process_xlsx_fast(path, out, anon, ui, size_mb):
    """Rows are read one sheet at a time (xlsx_stream) and write-only mode spools
    them to disk, so memory stays bounded however large the book is."""
    from openpyxl import Workbook
    from openpyxl.cell import WriteOnlyCell
    from openpyxl.styles import Font
    bold, cells, n_sheets = Font(bold=True), 0, 0
    ui.start(path.name, xlsx_est_rows(path), "rows")
    wb = Workbook(write_only=True)
    wb.properties.creator = wb.properties.lastModifiedBy = "anonymized"
    for title, hidden, rows in xlsx_stream(path):
        n_sheets += 1
        ws = wb.create_sheet(apply_rules(title, anon.rules)[:31])
        if hidden:
            ws.sheet_state = "hidden"
        rows, header = iter(rows), None
        for vals in rows:
            ui.advance()
            if vals:
                header = [str(v) if v is not None else None for v in vals]
                hc = []
                for v in vals:
                    c = WriteOnlyCell(ws, value=apply_rules(v, anon.rules) if isinstance(v, str) else v)
                    c.font = bold; hc.append(c)
                ws.append(hc)
                break
            ws.append([])

        def scrub_row(vals, header=header):
            outrow, n = [], 0
            for i, v in enumerate(vals):
                if isinstance(v, str) and v:
                    v = anon.scrub_str(v, header[i] if i < len(header) else None)
                    n += 1
                outrow.append(v)
            return outrow, n

        for outrow, n in anon.map(scrub_row, rows):
            ui.advance()
            cells += n
            ws.append(outrow)
    wb.save(xlsx_out(out))
    note = f"{n_sheets} sheet(s), {cells:,} cells, {size_mb:,.0f} MB streamed: values only"
    return note + (", -> .xlsx" if path.suffix.lower() == ".xlsm" else "")

def xlsx_out(out):
    """Values-only books can't carry macros: .xlsm is written as .xlsx."""
    return out.with_suffix(".xlsx") if out.suffix.lower() == ".xlsm" else out

def process_xlsx_full(path, out, anon, ui):
    """Every sheet: first non-empty row = header (used for identity-field
    detection, like CSV columns); every text cell below it is scrubbed, plus
    cell comments, hyperlinks and workbook metadata. Formatting is kept."""
    from openpyxl import load_workbook
    with CONSOLE.status(f"opening {path.name} ...", spinner="dots"):
        wb = load_workbook(path, keep_vba=path.suffix.lower() == ".xlsm")
    stats = {"cells": 0, "formulas": 0, "pivots": 0}
    last_rows = {ws.title: _last_row(ws) for ws in wb.worksheets}
    ui.start(path.name, sum(last_rows.values()), "rows")
    for ws in wb.worksheets:                       # includes hidden sheets
        last = last_rows[ws.title]
        if ws.title and apply_rules(ws.title, anon.rules) != ws.title:
            ws.title = apply_rules(ws.title, anon.rules)[:31]
        rows, header = iter(ws.iter_rows(max_row=last) if last else []), None
        for row in rows:
            ui.advance()
            if any(c.value not in (None, "") for c in row):
                header = [str(c.value) if c.value is not None else None for c in row]
                for c in row:                      # rules only: keeps real headers intact
                    if isinstance(c.value, str):
                        c.value = apply_rules(xl_safe(c.value), anon.rules)
                break

        def scrub_row(row, header=header):         # cells are changed in place
            n_cells = n_formulas = 0
            for i, c in enumerate(row):
                v = c.value
                if isinstance(v, str) and v:
                    v = xl_safe(v)
                    if c.data_type == "f":         # formula: scrub string literals, no NER
                        c.value = apply_rules(v, anon.rules)
                        n_formulas += 1
                    else:
                        c.value = anon.scrub_str(v, header[i] if i < len(header) else None)
                        n_cells += 1
                cm = getattr(c, "comment", None)
                if cm:
                    cm.text, cm.author = anon.scrub_str(cm.text), "anonymized"
                hl = getattr(c, "hyperlink", None)
                if hl and hl.target:
                    c.hyperlink = anon.scrub_str(hl.target)
            return n_cells, n_formulas

        for n_cells, n_formulas in anon.map(scrub_row, rows):
            ui.advance()
            stats["cells"] += n_cells; stats["formulas"] += n_formulas
        if getattr(ws, "_pivots", None):            # pivot caches hold a raw copy of the data
            stats["pivots"] += len(ws._pivots)
            ws._pivots = []
    p = wb.properties
    p.creator = p.lastModifiedBy = "anonymized"
    for attr in ("title", "subject", "description", "keywords", "category"):
        if isinstance(getattr(p, attr), str):
            setattr(p, attr, anon.scrub_str(getattr(p, attr)))
    wb.save(out)
    note = f"{len(wb.worksheets)} sheet(s), {stats['cells']:,} cells, {stats['formulas']} formulas"
    if stats["pivots"]:
        note += f", dropped {stats['pivots']} pivot table(s) (they cache raw data)"
    return note

def anonymize_json_stream(fh, f, anon, ui):
    """Stream a JSON document record by record: the elements of a top-level array,
    or of the arrays directly under a top-level object (Azure {"value": [...]},
    {"records": [...]} ...). Output is laid out like json.dumps(indent=2)."""
    js = JsonStream(fh)

    def array(depth, key=None):
        ind, n = "\n" + "  " * (depth + 1), 0
        f.write("[")
        dump = lambda v: json_dump_at(anon.walk(v, key, path=(key,) if key else ()), depth + 1)
        for s in anon.map(dump, (js.value() for _ in js.elements())):   # parsed in order, here
            f.write(("," if n else "") + ind + s)
            n += 1; ui.advance()
        f.write("\n" + "  " * depth + "]" if n else "]")

    if js.peek() == "[":
        array(0)
    elif js.peek() == "{":
        f.write("{")
        n = 0
        for k in js.keys():                         # top-level keys are kept as they are
            f.write(("," if n else "") + "\n  " + json.dumps(k, ensure_ascii=False) + ": ")
            n += 1
            if js.peek() == "[":
                array(1, k)
            else:
                f.write(json_dump_at(anon.walk(js.value(), k, path=(k,)), 1)); ui.advance()
        f.write("\n}" if n else "}")
    else:
        f.write(json_dump_at(anon.walk(js.value()), 0)); ui.advance()
    js.finish()

SUPPORTED = {".csv", ".tsv", ".tab", ".psv", ".ndjson", ".jsonl", ".json",
             ".log", ".txt", ".xlsx", ".xlsm"}
SKIP_NAMES = {"sample_manifest.json", "review_report.jsonl"}

def collect(inputs, outdir, extra_skip=(), recursive=True):
    """[(file, output path, display name)]. Folders are walked (recursively by
    default) and their sub-folder structure is mirrored under outdir; files given
    directly land in outdir itself. Only supported types are picked up from folders
    (plus .xls/.gz so they are reported as skipped instead of silently ignored)."""
    skip = SKIP_NAMES | {Path(x).name for x in extra_skip if x}
    dirs = [p for p in inputs if p.is_dir()]
    jobs, seen = [], set()
    for p in inputs:
        if p.is_dir():
            walker = p.rglob("*") if recursive else p.glob("*")
            for f in sorted(walker):
                rel = f.relative_to(p)
                if (not f.is_file() or any(part.startswith(".") for part in rel.parts)
                        or f.name in skip):
                    continue
                suf = f.suffix.lower()
                if suf not in SUPPORTED | {".xls", ".gz"}:
                    continue
                # several folders given: keep them apart as outdir/<folder>/...
                rel_out = Path(p.resolve().name) / rel if len(dirs) > 1 else rel
                jobs.append((f, rel_out))
        elif p.is_file():
            jobs.append((p, Path(p.name)))
        else:
            log(f"– not found, skipped: {p}", style="yellow")
    out = []
    for f, rel in jobs:
        dst, n = outdir / rel, 2
        while dst in seen:                       # same file name from different places
            dst = dst.with_name(f"{Path(rel.name).stem}_{n}{Path(rel.name).suffix}"); n += 1
        seen.add(dst)
        out.append((f, dst, str(rel)))
    return out

def process_file(path, out, anon, ui, xlsx_full_max_mb=40.0, label=None):
    out.parent.mkdir(parents=True, exist_ok=True)
    name = label or path.name
    if anon.reviewer:
        anon.reviewer.file = str(path)
    suf = path.suffix.lower()
    if suf == ".xls":
        return ui.skip(name, "legacy .xls not supported - re-save as .xlsx")
    if suf == ".gz":
        return ui.skip(name, "compressed - decompress first (or sample it with sample_files.py)")
    if suf in (".xlsx", ".xlsm"):
        return ui.finish(name, process_xlsx(path, out, anon, ui, xlsx_full_max_mb))
    # text formats: streamed record by record; the bar follows the bytes read
    size = path.stat().st_size
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as fh:  # newline="" keeps \r\n
        where = fh.buffer.tell
        if suf in (".csv", ".tsv", ".tab", ".psv"):
            head = fh.read(262144); fh.seek(0)
            delim = detect_delimiter(head, suf)               # ',' ';' tab '|' - by parse consistency
            eol = "\r\n" if "\r\n" in head[:65536] else "\n"
            rows = csv.reader(fh, delimiter=delim)             # multi-line cells ok
            header = next(rows, [])
            ui.start(name, size, "rows", where)
            with out.open("w", newline="", encoding="utf-8") as f:
                w = csv.writer(f, delimiter=delim, lineterminator=eol)
                w.writerow(header)
                scrub_row = lambda r: [anon.scrub_str(c, header[i] if i < len(header) else None)
                                       for i, c in enumerate(r)]
                for r in anon.map(scrub_row, rows):
                    w.writerow(r)
                    ui.advance()
        elif suf in (".ndjson", ".jsonl") or (suf == ".json" and is_ndjson(fh)):
            ui.start(name, size, "records", where)
            with out.open("w", encoding="utf-8") as f:
                dump = lambda l: json.dumps(anon.walk(json.loads(l)), ensure_ascii=False,
                                            separators=(",", ":")) + "\n"
                for s in anon.map(dump, (l for l in fh if l.strip())):
                    f.write(s)
                    ui.advance()
        elif suf == ".json":
            ui.start(name, size, "records", where)
            with out.open("w", encoding="utf-8") as f:
                anonymize_json_stream(fh, f, anon, ui)
        else:                                                 # .log, .txt and anything else: per line
            ui.start(name, size, "lines", where)
            with out.open("w", encoding="utf-8", newline="") as f:
                def scrub_line(l):
                    body = l.rstrip("\r\n")
                    return anon.scrub_str(body) + l[len(body):] if body.strip() else l
                for s in anon.map(scrub_line, fh):
                    f.write(s)
                    ui.advance()
    ui.finish(name)

def remove_partial(dst):
    for p in {dst, xlsx_out(dst)}:
        try:
            p.unlink(missing_ok=True)
        except OSError:
            pass

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="*", type=Path,
                    help="files and/or folders; folders are searched recursively")
    ap.add_argument("-o", "--outdir", type=Path, default=Path("anonymized"))
    ap.add_argument("--domains", default="", help="internal DNS suffixes, comma-separated")
    ap.add_argument("--model", default=DEFAULT_NER_MODEL,
                    help="Hugging Face id or local directory of the GLiNER2 PII model")
    ap.add_argument("--prefetch", action="store_true",
                    help="download the NER model into the local cache and exit")
    ap.add_argument("--threshold", type=float, default=0.4, help="NER confidence threshold")
    ap.add_argument("--name-threshold", type=float, default=0.6,
                    help="stricter threshold for person/name labels (model over-predicts names)")
    ap.add_argument("--no-ner", action="store_true", help="rules only (fast, no model)")
    ap.add_argument("--device", default="auto", choices=("auto", "cpu", "cuda", "mps"),
                    help="where the NER model runs; auto = CUDA GPU if present, else CPU "
                         "(mps = Apple GPU, opt-in)")
    ap.add_argument("--map", type=Path, help="write token->original map (SENSITIVE, keep local)")
    lx = ap.add_argument_group("identity columns & lexicon")
    lx.add_argument("--terms", type=Path,
                    help="extra terms to always replace, one per line, optionally 'term,CATEGORY' "
                         "(tenant aliases, project codenames, internal hostnames ...)")
    lx.add_argument("--id-columns", default="",
                    help="force columns as identity columns: 'Header=CATEGORY,Other Header=TENANT'")
    lx.add_argument("--keep-columns", default="",
                    help="never treat these columns as identity columns: 'Header,Other Header'")
    lx.add_argument("--no-lexicon", action="store_true",
                    help="don't replace identity-column values where they appear in free text")
    ap.add_argument("--xlsx-full-max-mb", type=float, default=40.0,
                    help="workbooks whose uncompressed sheet data is up to this size keep formatting, "
                         "comments and links; larger ones use fast values-only mode (default: 40)")
    ap.add_argument("--no-recursive", action="store_true",
                    help="for folders, only take files directly inside them")
    ap.add_argument("--no-progress", action="store_true", help="plain output, no progress bars")
    ap.add_argument("--verbose", action="store_true",
                    help="show library warnings and full tracebacks")
    rv = ap.add_argument_group("second pass (local LLM reviewer via LM Studio)")
    rv.add_argument("--review", action="store_true", help="enable the LLM review pass")
    rv.add_argument("--review-url", default="http://127.0.0.1:1234/v1",
                    help="OpenAI-compatible base URL (default: LM Studio)")
    rv.add_argument("--review-model", help="model id; default = first model loaded in LM Studio")
    rv.add_argument("--review-apply", action="store_true",
                    help="pseudonymize flagged spans (default: dry run, report only)")
    rv.add_argument("--review-report", type=Path, default=Path("review_report.jsonl"),
                    help="JSONL of flagged spans (SENSITIVE: contains the leaked values)")
    rv.add_argument("--review-min-len", type=int, default=20,
                    help="only review strings at least this long (skips short field values)")
    rv.add_argument("--review-workers", type=int, default=4,
                    help="records reviewed in parallel, i.e. LLM requests in flight (default: 4). "
                         "Match the server: LM Studio 'Max Concurrent Predictions', vLLM / "
                         "llama-server --parallel on a GPU box can take 16+")
    rv.add_argument("--allow-remote-review", action="store_true",
                    help="permit a non-localhost --review-url (private cloud endpoint only)")
    a = ap.parse_args()
    if a.prefetch:
        return prefetch_model(a.model)
    if not a.files:
        ap.error("no input files given")
    if not KEY:
        sys.exit("Set ANON_KEY first:  export ANON_KEY=$(openssl rand -hex 32)")
    od = a.outdir.resolve()
    for p in a.files:
        if p.is_dir() and (od == p.resolve() or p.resolve() in od.parents):
            sys.exit(f"--outdir {a.outdir} is inside the input folder {p} - pick a separate folder "
                     "so originals are never overwritten or re-processed")
    jobs = collect(a.files, a.outdir, extra_skip=(a.map, a.review_report),
                   recursive=not a.no_recursive)
    if not jobs:
        sys.exit("no supported input files found")
    for spec in filter(None, (x.strip() for x in a.id_columns.split(","))):
        h, _, c = spec.partition("=")
        COLUMN_OVERRIDES[norm_header(h)] = re.sub(r"[^A-Z]", "", c.upper()) or "ID"
    for h in filter(None, (x.strip() for x in a.keep_columns.split(","))):
        COLUMN_OVERRIDES[norm_header(h)] = None
    if not a.verbose:
        quiet_ml_libs()
    a.outdir.mkdir(parents=True, exist_ok=True)
    state = {"ui": None, "current": None, "reviewer": None, "done": 0,
             "started": time.monotonic()}

    def run():
        ner = None if a.no_ner else NER(a.model, a.threshold, a.name_threshold, a.device)  # fail fast
        reviewer = Reviewer(a.review_url, a.review_model, a.review_apply, a.review_report,
                            a.allow_remote_review, a.review_min_len) if a.review else None
        state["reviewer"] = reviewer
        if any(p.is_dir() for p in a.files):
            log(f"{len(jobs)} file(s) found")
        lexicon = Lexicon()
        for d in filter(None, (x.strip() for x in a.domains.split(","))):
            lexicon.add_domain(d)
        if a.terms:
            log(f"{load_terms(a.terms, lexicon)} term(s) loaded from {a.terms}")
        with CONSOLE.status(f"scanning {len(jobs)} file(s) for names, tenants, ids ...", spinner="dots"):
            cols = prescan(jobs, lexicon)
        by_sig = {}
        for label, pairs in cols.items():
            by_sig.setdefault(tuple(pairs), []).append(label)
        for pairs, labels in by_sig.items():
            where = labels[0] if len(labels) == 1 else f"{labels[0]} +{len(labels) - 1} more"
            log(f"identity columns [{where}]: " + " · ".join(f"{h} → {c}" for h, c in pairs[:12])
                + (f" · +{len(pairs) - 12} more" if len(pairs) > 12 else ""))
        if not cols:
            log("no identity columns recognised - use --id-columns 'Header=CATEGORY' if needed",
                style="yellow")
        if a.no_lexicon:
            lexicon = Lexicon()
        log(lexicon.compile().summary())
        # internal domains: --domains plus those learnt (UPN suffixes, agent domains, mailboxes)
        anon = Anonymizer(build_rules(sorted(d for d in lexicon.domains if "." in d)), ner,
                          reviewer=reviewer, lexicon=lexicon,
                          workers=max(1, a.review_workers) if reviewer else 1)
        try:
            with UI(len(jobs), ner, reviewer, enabled=not a.no_progress) as ui:
                state["ui"] = ui
                for f, dst, label in jobs:
                    try:
                        if dst.resolve() == f.resolve():
                            raise ValueError("output would overwrite the input")
                        state["current"] = dst
                        process_file(f, dst, anon, ui, a.xlsx_full_max_mb, label)
                        state["current"] = None
                        state["done"] += 1
                    except Exception as e:
                        state["current"] = None
                        remove_partial(dst)            # streamed output stops where the error was
                        if a.verbose:
                            raise
                        ui.fail(label, f"{type(e).__name__}: {e}"[:200])
        finally:
            if reviewer:
                reviewer.close()
        if a.map:
            a.map.parent.mkdir(parents=True, exist_ok=True); a.map.write_text(json.dumps(MAPPING, indent=2), encoding="utf-8")
            log(f"mapping written to {a.map} - treat it like the raw data", style="yellow")
        log(f"{ui.n_ok} file(s) anonymized, {ui.n_fail} failed -> {a.outdir}/  "
            f"({time.monotonic() - state['started']:.1f}s)",
            style="bold green" if not ui.n_fail else "bold red")
        return 1 if ui.n_fail else 0

    def on_cancel():
        ui = state["ui"]
        if ui is not None:
            try:
                ui.progress.stop()
            except Exception:
                pass
        CONSOLE.show_cursor(True)
        cur = state["current"]
        if cur is not None:                           # half-written output: never leave it behind
            remove_partial(cur)
        rv = state["reviewer"]
        if rv is not None and rv.report:
            try:
                rv.report.flush()
            except Exception:
                pass
        if a.map and MAPPING:
            try:
                a.map.parent.mkdir(parents=True, exist_ok=True); a.map.write_text(json.dumps(dict(MAPPING), indent=2), encoding="utf-8")
            except Exception:
                pass
        log(f"cancelled - {state['done']} file(s) completed in {a.outdir}/"
            f"{', partial output of the current file removed' if cur is not None else ''}"
            f" ({time.monotonic() - state['started']:.1f}s)", style="bold yellow")

    sys.exit(run_cancellable(run, on_cancel))

if __name__ == "__main__":
    main()
