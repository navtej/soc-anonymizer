#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "gliner2[local]>=2.1,<3",  # [local] = on-device inference (torch, transformers)
#     "openpyxl>=3.1",           # .xlsx / .xlsm
#     "python-calamine>=0.2",    # fast reading of large .xlsx (Rust)
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
an unscrubbed copy of the data. Larger books use a fast streaming mode: values
only (formulas become cached values; comments/links/formatting are not copied). Numbers stored as numeric cells
(e.g. a phone number typed as 9814012345) are not touched.

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
    ("DOMAIN",   r"upn suffix|nt domain|dns domain|domain( name)?|user domain|account domain"),
    ("USERID",   r"(assignee|reporter|creator|user|account|actor|caller|owner|analyst|approver|requester|"
                 r"watcher|participant|object|principal)s? id|account id|aad user id|user object id"),
    ("TENANT",   r"(tenant|customer|client|company|organi[sz]ation|org)( (display )?name)?|subscription name"),
    ("EMAIL",    r"e ?mail( address)?|mail|upn|user principal name|identity|sender|recipient"),
    # NB: a bare 'DisplayName' is NOT a user column - in Sentinel it is the alert title.
    ("USER",     r"assignee|reporter|creator|owner|analyst( name)?|approvers?|watchers?|request participants?|"
                 r"user( ?name)?|account( ?name)?|target user ?name|subject user ?name|caller|initiated by|"
                 r"(created|modified|resolved|requested|reviewed|assigned|closed) by|requester|actor|"
                 r"user display ?name|src user|dst user|employee( name)?|full name"),
    ("HOST",     r"host( ?name)?|computer( ?name)?|device( ?name)?|workstation( ?name)?|machine( ?name)?|"
                 r"src host|dst host|endpoint( name)?|asset( name)?|net ?bios ?name|fqdn"),
]
# Column-only categories: replaced in their own column, but NOT chased through free text
# (e.g. 'Microsoft' as VendorName should not wipe every 'Microsoft' from descriptions).
COLUMN_ONLY = {"PROVIDER", "VENDOR", "SYSTEM", "VENDORID", "ISSUEID"}

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

def json_field_category(parent, key):
    """Category for parent[key]: entity-type aware for Sentinel entities, else by key name."""
    if not isinstance(key, str):
        return None
    t = parent.get("Type") or parent.get("type") if isinstance(parent, dict) else None
    if isinstance(t, str):
        m = ENTITY_FIELDS.get(t.lower())
        if m is not None and key.lower() in m:
            return m[key.lower()]
    return column_category(key)

def resolve_category(cat, value):
    """ENTITY columns hold either a UPN or a host name; USER columns sometimes hold UPNs."""
    if cat == "ENTITY":
        return "EMAIL" if "@" in value else "HOST"
    if cat in ("USER", "EMAIL") and "@" in value:
        return "EMAIL"
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

def column_category(header):
    if not header:
        return None
    if header in _COL_CACHE:
        return _COL_CACHE[header]
    n = norm_header(header)
    if n in COLUMN_OVERRIDES:
        cat = COLUMN_OVERRIDES[n]
    else:
        cat = next((c for c, rx in _COLUMN_RX if rx.fullmatch(n)), None)
    _COL_CACHE[header] = cat
    return cat

# ---------- lexicon: known identifiers, replaced wherever they appear in free text ----------
STOP_TERMS = {"unassigned", "none", "null", "n/a", "na", "nil", "-", "--", "unknown", "system", "admin",
              "administrator", "automation for jira", "jira", "service desk", "internal", "test", "default",
              "true", "false", "yes", "no", "high", "low", "medium", "critical", "open", "closed"}
CORP_SUFFIX = re.compile(r"[\s,.]+(private|pvt\.?|ltd\.?|limited|inc\.?|incorporated|corp\.?|corporation|"
                         r"llc|l\.l\.c\.|llp|plc|gmbh|ag|sa|bv|co\.?|company|group|holdings?|"
                         r"technologies|technology|tech|solutions|services|systems|india|global)\.?$", re.I)

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
        self.counts = {}
        self.rx = None

    def _put(self, term, cat, canon, weak=False):
        """weak = a derived single-word variant (first name, tenant short name): only
        matched when written like a name (Capitalised or ALL CAPS), so a tenant called
        'Global Bank' doesn't wipe out every 'global' in the text."""
        t = term.strip()
        if len(t) < 3 or t.lower() in STOP_TERMS or t.isdigit():
            return
        if weak and " " in t:
            weak = False
        old = self.terms.get(t.lower())
        if old is None or (old[2] and not weak):
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
        if cat in COLUMN_ONLY or v.isdigit():
            return                          # bare numbers in prose are too ambiguous to chase
        cat = resolve_category(cat, v)
        if cat in ("USER", "TENANT", "USERID", "TENANTID", "EMAIL", "HOST", "HOSTID", "SUBSCRIPTIONID",
                   "RG", "WORKSPACE", "DOMAIN", "SID", "TERM"):
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
                core = v
                while CORP_SUFFIX.search(core):
                    core = CORP_SUFFIX.sub("", core).strip()
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
        for dom in self.email_domains:
            if registrable_label(dom) in known:
                self.add_domain(dom)
        for part, fulls in self.names.items():
            if part in self.terms or part in STOP_TERMS:
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
def build_rules(domains):
    rules = [
        ("SECRET", re.compile(r"\beyJ[\w-]{10,}\.[\w-]{10,}\.[\w-]{10,}\b")),             # JWT
        ("SECRET", re.compile(r"(?i)\b(?:password|passwd|pwd|secret|token|apikey|api_key|sig)=([^&\s\"']+)")),
        # defanged / URL-encoded: john%40acme.com, john[@]acme[.]com, john (at) acme (dot) com
        ("EMAIL_OBF", re.compile(r"(?i)\b([\w.+'-]+)\s?(?:%40|\[@\]|\(@\)|\[at\]|\(at\)|\{at\})\s?"
                                 r"([\w-]+(?:\s?(?:\.|\[\.\]|\(\.\)|\[dot\]|\(dot\)|%2e)\s?[\w-]+)+)\b")),
        ("EMAIL", re.compile(r"\b[\w.+'%-]+@[\w-]+(?:\.[\w-]+)+\b")),
        # Azure resource paths and portal links
        ("SUBSCRIPTIONID", re.compile(r"(?i)(?:/subscriptions/|subscriptionId[/=])"
                                      r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})")),
        ("RG", re.compile(r"(?i)(?:/resourceGroups?/|resourceGroup[/=])([^/\s\"'?#&\\]+)")),
        ("WORKSPACE", re.compile(r"(?i)/workspaces/([^/\s\"'?#&\\]+)")),
        ("HOST", re.compile(r"(?i)/(?:virtualMachines|machines|computers)/([^/\s\"'?#&\\]+)")),
        ("DOMAIN", re.compile(r"(?i)\b([\w-]+)\.onmicrosoft\.com\b")),
        ("DOMAIN", re.compile(r"(?i)\bDC=([\w-]+)")),
        ("SID", re.compile(r"\bS-1-5-21-\d+-\d+-\d+-\d+\b")),
        ("GUID", re.compile(r"(?<![0-9A-Fa-f-])[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?![0-9A-Fa-f-])")),
        ("MAC", re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")),
        ("IPV4", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")),
        ("IPV6", re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b")),
        ("USER", re.compile(r"(?i)(?<=[\\/]users[\\/])[^\\/\s\"']+")),                     # C:\Users\x, /Users/x
        ("USER", re.compile(r"(?i)(?<=/home/)[^/\s\"']+")),
        ("USER", re.compile(r"\b[A-Z][A-Z0-9-]{1,14}\\([A-Za-z0-9._$-]{2,})\b")),         # DOMAIN\user
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
TOKEN_RX = re.compile(r"\b(?:[A-Z]+_[0-9a-f]{8}|user_[0-9a-f]{8}@example\.com|TKT-\d{7})\b")

def prefetch_model(model_name):
    """Download the NER weights into the Hugging Face cache (no data is sent)."""
    if os.environ.get("HF_HUB_OFFLINE") == "1":
        sys.exit("Unset HF_HUB_OFFLINE for the one-time download:  unset HF_HUB_OFFLINE")
    from huggingface_hub import snapshot_download
    path = snapshot_download(model_name)
    log(f"model cached at {path}\nfrom now on you can run with HF_HUB_OFFLINE=1", style="green")

class NER:
    def __init__(self, model_name, threshold, name_threshold):
        self.hits = 0
        err = None
        with CONSOLE.status(f"loading NER model {model_name} ...", spinner="dots"):
            from gliner2 import GLiNER2
            try:
                self.model = GLiNER2.from_pretrained(model_name)
            except Exception as e:  # missing from cache / offline / wrong id
                err = e
        if err:
            sys.exit(f"Could not load NER model '{model_name}': {type(err).__name__}.\n"
                     f"Download it once (model weights only, none of your data is sent):\n"
                     f"  unset HF_HUB_OFFLINE && uv run {Path(sys.argv[0]).name} --prefetch\n"
                     f"or pass --model /path/to/local/model_dir, or use --no-ner.")
        log(f"NER model: {model_name}")
        self.threshold, self.name_threshold = threshold, max(threshold, name_threshold)

    def __call__(self, text):
        if looks_like_blob(text):
            return text
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
            self.calls += 1
            leaks = self._ask(chunk)
            self.on_call()
            for leak in leaks:
                span, kind = str(leak.get("text", "")).strip(), str(leak.get("type", "PII"))
                # accept only real, non-placeholder spans: the LLM can flag, never invent
                if len(span) < 3 or span not in out or span in MAPPING or TOKEN_RX.fullmatch(span):
                    continue
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

# ---------- recursive walker ----------
class Anonymizer:
    def __init__(self, rules, ner=None, ner_min_len=25, reviewer=None, lexicon=None):
        self.rules, self.ner, self.ner_min_len = rules, ner, ner_min_len
        self.reviewer, self.lexicon = reviewer, lexicon or Lexicon().compile()
        self.email_rules = [r for r in rules if r[0] in ("EMAIL", "EMAIL_OBF")]
        self.other_rules = [r for r in rules if r[0] not in ("EMAIL", "EMAIL_OBF")]

    def pseudo_field(self, cat, s):
        if cat == "ISSUEKEY":
            return self.lexicon.apply(s) if " " in s.strip() else pseudo(cat, s.upper())
        if cat == "DOMAIN":
            return pseudo("DOMAIN", s.strip().lower())
        return pseudo(resolve_category(cat, s), s)

    def scrub_key(self, k):
        """JSON keys can carry PII too ({"rahul@acme.com": ...}); no NER, rules + lexicon only."""
        if not isinstance(k, str) or len(k) < 3 or k.startswith("$"):
            return k
        return apply_rules(self.lexicon.apply(apply_rules(k, self.email_rules)), self.other_rules)

    def scrub_str(self, s, key=None, cat=None):
        t = s.strip()
        if t[:1] in "{[" and len(t) > 1:
            try:
                return json.dumps(self.walk(json.loads(t)), ensure_ascii=False, separators=(",", ":"))
            except ValueError:
                pass
        cat = column_category(key) if cat is None else cat
        if cat and s.strip():
            return self.pseudo_field(cat, s)
        s = apply_rules(s, self.email_rules)  # whole e-mail addresses first (also defanged / %40)
        s = self.lexicon.apply(s)             # known names / tenants / keys -> same tokens as their columns
        s = apply_rules(s, self.other_rules)
        if self.ner and len(s) >= self.ner_min_len and re.search(r"[A-Za-z]{3,} [A-Za-z]", s):
            s = "".join(self.ner(c) for c in chunks(s))
        if self.reviewer:
            s = self.reviewer(s)
        return s

    def walk(self, obj, key=None, cat=None):
        if isinstance(obj, dict):
            out = {}
            for k, v in obj.items():
                c = json_field_category(obj, k)
                out[self.scrub_key(k)] = self.walk(v, k, c or "")   # "" = known: not an identity field
            return out
        if isinstance(obj, list):
            return [self.walk(v, key, cat) for v in obj]
        if isinstance(obj, str):
            return self.scrub_str(obj, key, cat if cat else (None if cat is None else ""))
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
        from rich.progress import (BarColumn, MofNCompleteColumn, Progress, TaskProgressColumn,
                                   TextColumn, TimeElapsedColumn, TimeRemainingColumn)
        from rich.table import Column
        self.ner, self.reviewer, self.enabled = ner, reviewer, enabled
        self.progress = Progress(
            TextColumn("{task.description}", markup=False, table_column=Column(width=NAME_W, no_wrap=True)),
            BarColumn(bar_width=28), TaskProgressColumn(),
            MofNCompleteColumn(table_column=Column(justify="right", min_width=11)),
            TextColumn("{task.fields[unit]}", markup=False, table_column=Column(width=7)),
            TimeElapsedColumn(), TextColumn("eta", style="dim"), TimeRemainingColumn(),
            TextColumn("{task.fields[info]}", markup=False, style="cyan"),
            console=CONSOLE, transient=False, disable=not enabled, refresh_per_second=8)
        self.total = self.progress.add_task(fit("TOTAL"), total=n_files, unit="files", info="")
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

    def start(self, name, total, unit):
        self.t0 = time.monotonic()
        self.unit, self.count = unit, total
        self.task = self.progress.add_task(fit(name), total=max(total, 1), unit=unit, info=self._info())

    def advance(self, n=1):
        self.progress.update(self.task, advance=n, info=self._info())

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
        self.progress.advance(self.total)
        self._line("–", "yellow", name, why)

    def _close_task(self):
        if self.task is not None:
            self.progress.remove_task(self.task)
            self.task = None
        self.progress.advance(self.total)

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
                    walk_str(v)

    def walk_str(v):
        try:
            walk(json.loads(v))
        except ValueError:
            pass

    def walk(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                c = json_field_category(obj, k)
                if c and isinstance(v, str) and not v.lstrip()[:1] in ("{", "["):
                    lexicon.add(c, v)
                elif isinstance(v, str) and v.lstrip()[:1] in ("{", "["):
                    walk_str(v)
                else:
                    walk(v)
        elif isinstance(obj, list):
            for v in obj:
                walk(v)

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
                from python_calamine import CalamineWorkbook
                book = CalamineWorkbook.from_path(str(f))
                for meta in book.sheets_metadata:
                    if not str(meta.typ).endswith(".WorkSheet"):
                        continue
                    rows = book.get_sheet_by_name(meta.name).to_python(skip_empty_area=False)
                    h = next((i for i, r in enumerate(rows) if _nonempty(r)), None)
                    if h is not None:
                        take(f"{label} › {meta.name}", [str(x) for x in rows[h]], rows[h + 1:])
            elif suf in (".ndjson", ".jsonl", ".json"):
                raw = f.read_text(encoding="utf-8-sig", errors="replace")
                try:
                    walk(json.loads(raw))
                except ValueError:
                    for line in raw.splitlines():
                        if line.strip():
                            try:
                                walk(json.loads(line))
                            except ValueError:
                                pass
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

def xl_safe(v):
    """openpyxl refuses control characters in cells (Excel stores them as _xHHHH_
    escapes, which calamine / openpyxl decode on read); replace them with U+FFFD
    before scrubbing, so names split by them are still matched."""
    return XL_ILLEGAL.sub("\ufffd", v) if isinstance(v, str) else v

def process_xlsx(path, out, anon, ui, full_max_mb):
    """Small books: full-fidelity in-place scrub. Large books (or sheets formatted
    down to row 1,048,576): fast calamine read + streaming write, values only."""
    data_mb = xlsx_sheet_mb(path)
    if data_mb <= full_max_mb:
        return process_xlsx_full(path, out, anon, ui)
    return process_xlsx_fast(path, out, anon, ui, data_mb)

def process_xlsx_fast(path, out, anon, ui, size_mb):
    from openpyxl import Workbook
    from openpyxl.cell import WriteOnlyCell
    from openpyxl.styles import Font
    from python_calamine import CalamineWorkbook
    bold, sheets, total = Font(bold=True), [], 0
    with CONSOLE.status(f"reading {path.name} ({size_mb:,.0f} MB of sheet data) ...", spinner="dots") as st:
        book = CalamineWorkbook.from_path(str(path))
        for meta in book.sheets_metadata:
            if not str(meta.typ).endswith(".WorkSheet"):
                continue
            st.update(f"reading {path.name} ({size_mb:,.0f} MB of sheet data) › sheet '{meta.name}' ...")
            rows = book.get_sheet_by_name(meta.name).to_python(skip_empty_area=False)
            sheets.append((meta.name, not str(meta.visible).endswith(".Visible"), rows))
            total += len(rows)
    ui.start(path.name, total, "rows")
    wb, cells = Workbook(write_only=True), 0
    wb.properties.creator = wb.properties.lastModifiedBy = "anonymized"
    for name, hidden, rows in sheets:
        ws = wb.create_sheet(apply_rules(name, anon.rules)[:31])
        if hidden:
            ws.sheet_state = "hidden"
        header = None
        for row in rows:
            ui.advance()
            vals = [None if v == "" else xl_safe(v) for v in row]
            if header is None:
                if _nonempty(vals):
                    header = [str(v) if v is not None else None for v in vals]
                    hc = []
                    for v in vals:
                        c = WriteOnlyCell(ws, value=apply_rules(v, anon.rules) if isinstance(v, str) else v)
                        c.font = bold; hc.append(c)
                    ws.append(hc)
                else:
                    ws.append([])
                continue
            outrow = []
            for i, v in enumerate(vals):
                if isinstance(v, str) and v:
                    v = anon.scrub_str(v, header[i] if i < len(header) else None)
                    cells += 1
                outrow.append(v)
            ws.append(outrow)
    wb.save(out.with_suffix(".xlsx") if out.suffix.lower() == ".xlsm" else out)
    note = f"{len(sheets)} sheet(s), {cells:,} cells, fast mode: values only"
    return note + (", -> .xlsx" if path.suffix.lower() == ".xlsm" else "")

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
        header = None
        for row in (ws.iter_rows(max_row=last) if last else []):
            ui.advance()
            if header is None:
                if any(c.value not in (None, "") for c in row):
                    header = [str(c.value) if c.value is not None else None for c in row]
                    for c in row:                  # rules only: keeps real headers intact
                        if isinstance(c.value, str):
                            c.value = apply_rules(xl_safe(c.value), anon.rules)
                continue
            for i, c in enumerate(row):
                v = c.value
                if isinstance(v, str) and v:
                    v = xl_safe(v)
                    if c.data_type == "f":         # formula: scrub string literals, no NER
                        c.value = apply_rules(v, anon.rules)
                        stats["formulas"] += 1
                    else:
                        c.value = anon.scrub_str(v, header[i] if i < len(header) else None)
                        stats["cells"] += 1
                cm = getattr(c, "comment", None)
                if cm:
                    cm.text, cm.author = anon.scrub_str(cm.text), "anonymized"
                hl = getattr(c, "hyperlink", None)
                if hl and hl.target:
                    c.hyperlink = anon.scrub_str(hl.target)
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

def walk_json_top(data, anon, ui, name):
    """Walk a JSON document advancing the bar per record: per element of a
    top-level array, or per element of any array directly under a top-level
    object (Azure {"value": [...]}, {"records": [...]} ...)."""
    if isinstance(data, list):
        ui.start(name, len(data), "records")
        res = []
        for v in data:
            res.append(anon.walk(v)); ui.advance()
        return res
    if isinstance(data, dict):
        ui.start(name, sum(len(v) if isinstance(v, list) else 1 for v in data.values()), "records")
        res = {}
        for k, v in data.items():
            if isinstance(v, list):
                res[k] = []
                for x in v:
                    res[k].append(anon.walk(x, k)); ui.advance()
            else:
                res[k] = anon.walk(v, k); ui.advance()
        return res
    ui.start(name, 1, "values")
    res = anon.walk(data); ui.advance()
    return res

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
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as fh:
        raw = fh.read()                                   # newline="" keeps \r\n vs \n intact
    if suf in (".csv", ".tsv", ".tab", ".psv"):
        delim = detect_delimiter(raw[:262144], suf)       # ',' ';' tab '|' - by parse consistency
        eol = "\r\n" if "\r\n" in raw[:65536] else "\n"
        rows = list(csv.reader(io.StringIO(raw, newline=""), delimiter=delim))  # multi-line cells ok
        header = rows[0] if rows else []
        ui.start(name, max(len(rows) - 1, 0), "rows")
        res = [header]
        for r in rows[1:]:
            res.append([anon.scrub_str(c, header[i] if i < len(header) else None)
                        for i, c in enumerate(r)])
            ui.advance()
        with out.open("w", newline="", encoding="utf-8") as f:
            csv.writer(f, delimiter=delim, lineterminator=eol).writerows(res)
    elif suf in (".log", ".txt"):
        lines = raw.splitlines(keepends=True)
        ui.start(name, len(lines), "lines")
        with out.open("w", encoding="utf-8", newline="") as f:
            for l in lines:
                body = l.rstrip("\r\n")
                f.write(anon.scrub_str(body) + l[len(body):] if body.strip() else l)
                ui.advance()
    elif suf in (".ndjson", ".jsonl") or (suf == ".json" and _is_ndjson(raw)):
        lines = [l for l in raw.splitlines() if l.strip()]
        ui.start(name, len(lines), "records")
        res = []
        for l in lines:
            res.append(json.dumps(anon.walk(json.loads(l)), ensure_ascii=False, separators=(",", ":")))
            ui.advance()
        out.write_text("\n".join(res) + "\n", encoding="utf-8")
    elif suf == ".json":
        data = walk_json_top(json.loads(raw), anon, ui, name)
        out.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    else:
        ui.start(name, 1, "file")
        out.write_text(anon.scrub_str(raw), encoding="utf-8")
        ui.advance()
    ui.finish(name)

def _is_ndjson(raw):
    try:
        json.loads(raw); return False
    except ValueError:
        return True

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
        ner = None if a.no_ner else NER(a.model, a.threshold, a.name_threshold)  # fail fast
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
        anon = Anonymizer(build_rules([d.strip() for d in a.domains.split(",") if d.strip()]), ner,
                          reviewer=reviewer, lexicon=lexicon)
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
        if cur is not None and cur.exists():          # half-written output: never leave it behind
            try:
                cur.unlink()
            except OSError:
                pass
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
