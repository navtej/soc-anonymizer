"""Regression tests for soc_anonymize.py - synthetic data only, rules mode (no NER download).

Run:  uv run --with pytest --with rich --with openpyxl --with python-calamine pytest -q tests
"""
import csv
import importlib.util
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

import fixtures

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "soc_anonymize.py"
ENV = dict(os.environ, ANON_KEY="test-key")


def load_module():
    spec = importlib.util.spec_from_file_location("soc_anonymize", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.KEY = b"test-key"
    return mod


def run(args, cwd, check=True):
    r = subprocess.run([sys.executable, str(SCRIPT), *map(str, args), "--no-progress"],
                       cwd=cwd, env=ENV, capture_output=True, text=True, timeout=300)
    if check:
        assert r.returncode == 0, r.stdout + r.stderr
    return r


def read_csv(p):
    return list(csv.reader(open(p, newline="", encoding="utf-8")))


def token_index(mapping):
    """original (lowercased) -> set of tokens"""
    inv = {}
    for tok, orig in mapping.items():
        inv.setdefault(orig.lower(), set()).add(tok)
    return inv


def assert_mapping_sane(mapping):
    inv = token_index(mapping)
    multi = {k: v for k, v in inv.items() if len(v) > 1}
    assert not multi, f"same original got several tokens: {multi}"
    double = [k for k, v in mapping.items() if v in mapping]
    assert not double, f"tokens were anonymized again: {double}"


def all_text(folder):
    out = []
    for p in Path(folder).rglob("*"):
        if p.is_file() and p.suffix in (".csv", ".json", ".ndjson", ".log", ".txt") and p.name != "map.json":
            out.append(p.read_text(encoding="utf-8", errors="ignore"))
        if p.suffix == ".xlsx":
            from openpyxl import load_workbook
            wb = load_workbook(p)
            out += [str(c.value) for ws in wb.worksheets for r in ws.iter_rows() for c in r if c.value]
    return "\n".join(out)


# --------------------------------------------------------------------------- Jira

def test_jira_identity_columns_and_free_text(tmp_path):
    src = fixtures.build_jira(tmp_path)
    run([src.name, "-o", "out", "--no-ner", "--map", "out/map.json"], tmp_path)
    out = read_csv(tmp_path / "out" / src.name)
    H, row = out[0], out[1]
    m = json.load(open(tmp_path / "out" / "map.json"))
    assert_mapping_sane(m)

    assert row[H.index("Issue key")].startswith("TKT-")
    assert row[H.index("Issue id")].startswith("ISSUEID_")
    assert row[H.index("Assignee")].startswith("USER_")
    assert row[H.index("Assignee Id")].startswith("USERID_")
    assert row[H.index("Custom field (Tenant Name)")].startswith("TENANT_")

    user, tenant, key = (row[H.index(c)] for c in ("Assignee", "Custom field (Tenant Name)", "Issue key"))
    assert user in row[H.index("Summary")] and tenant in row[H.index("Summary")]
    assert user in row[H.index("Custom field (Description.)")]
    assert key in row[H.index("Custom field (Triage Evidence(QC))")]

    text = open(tmp_path / "out" / src.name, encoding="utf-8").read().lower()
    left = [s for s in fixtures.JIRA_SECRETS if s.lower() in text]
    assert not left, f"leaked: {left}"


def test_jira_non_identity_columns_unchanged(tmp_path):
    src = fixtures.build_jira(tmp_path)
    run([src.name, "-o", "out", "--no-ner"], tmp_path)
    a, b = read_csv(src), read_csv(tmp_path / "out" / src.name)
    for col in ["Status", "Custom field (Severity)", "Created", "Custom field (Risk Score)",
                "Custom field (Threat Category)", "Issue Type"]:
        i = a[0].index(col)
        assert [r[i] for r in a] == [r[i] for r in b], col


# --------------------------------------------------------------------------- Sentinel

def test_sentinel_columns_json_and_consistency(tmp_path):
    src = fixtures.build_sentinel(tmp_path)
    run([src.name, "-o", "out", "--no-ner", "--map", "out/map.json"], tmp_path)
    out = read_csv(tmp_path / "out" / src.name)
    H, row = out[0], out[1]
    m = json.load(open(tmp_path / "out" / "map.json"))
    assert_mapping_sane(m)

    expect = {"TenantId": "TENANTID_", "ProviderName": "PROVIDER_", "VendorName": "VENDOR_",
              "VendorOriginalId": "VENDORID_", "SourceComputerId": "HOSTID_", "SourceSystem": "SYSTEM_",
              "WorkspaceSubscriptionId": "SUBSCRIPTIONID_", "WorkspaceResourceGroup": "RG_"}
    for col, prefix in expect.items():
        assert row[H.index(col)].startswith(prefix), (col, row[H.index(col)])
    # alert title must survive
    assert row[H.index("DisplayName")] == "Suspicious inbox forwarding rule"
    assert row[H.index("AlertName")] == "Suspicious inbox forwarding rule"
    # tenant GUID glued to '_' in AlertType
    assert row[H.index("AlertType")].startswith(row[H.index("TenantId")] + "_")
    # same RG / subscription token inside paths and links
    for col in ("ResourceId", "AlertLink", "ExtendedLinks"):
        assert row[H.index("WorkspaceResourceGroup")] in row[H.index(col)], col
        assert row[H.index("WorkspaceSubscriptionId")] in row[H.index(col)], col
    # entity JSON: split UPN, hosts, mailbox
    ent = {e["Type"]: e for e in json.loads(row[H.index("Entities")])}
    assert ent["account"]["Name"].startswith("USER_") and ent["account"]["UPNSuffix"].startswith("DOMAIN_")
    assert ent["host"]["HostName"].startswith("HOST_") and ent["host"]["OMSAgentID"].startswith("HOSTID_")
    email_tok = row[H.index("CompromisedEntity")]
    assert ent["mailbox"]["MailboxPrimaryAddress"] == email_tok == ent["mailMessage"]["Recipient"]
    ext = json.loads(row[H.index("ExtendedProperties")])
    assert not any("@acmeholdings" in k for k in ext), "e-mail used as a JSON key leaked"

    text = open(tmp_path / "out" / src.name, encoding="utf-8").read().lower()
    left = [s for s in fixtures.SENTINEL_SECRETS if s.lower() in text]
    assert not left, f"leaked: {left}"


# --------------------------------------------------------------------------- multi-file

def test_cross_file_one_token_per_value(tmp_path):
    d = fixtures.build_multi(tmp_path / "multi")
    run(["multi", "-o", "out", "--no-ner", "--id-columns", "Ticket=ISSUEKEY", "--map", "out/map.json"], tmp_path)
    m = json.load(open(tmp_path / "out" / "map.json"))
    assert_mapping_sane(m)
    inv = token_index(m)
    for orig in ["priya sharma", "acme holdings pvt ltd", "globex corporation", "initech inc", "mssoc-1203"]:
        assert len(inv[orig]) == 1, orig
    text = all_text(tmp_path / "out")
    left = [s for s in ["Priya", "Sharma", "Acme", "Globex", "GLOBEX", "Initech", "Desai", "Verma", "MSSOC",
                        "mssoc", "Turner"] if s in text]
    assert not left, f"leaked: {left}"


def test_weak_variants_only_when_name_cased(tmp_path):
    fixtures.build_multi(tmp_path / "multi")
    run(["multi/weak.csv", "-o", "out", "--no-ner"], tmp_path)
    s = (tmp_path / "out" / "weak.csv").read_text()
    assert "global admin role reviewed" in s and "will escalate" in s
    assert "Global Bank" not in s and "Will checked" not in s and "GLOBAL logs" not in s


# --------------------------------------------------------------------------- units

@pytest.mark.parametrize("text", [
    "plain priya.sharma@acmeholdings.com end", "Priya.Sharma@AcmeHoldings.COM",
    "url ?u=priya.sharma%40acmeholdings.com&x=1", "defanged priya.sharma[@]acmeholdings[.]com",
    "spoken priya.sharma (at) acmeholdings (dot) com", "SMTP:Priya.Sharma@acmeholdings.com;"])
def test_email_forms_share_one_token(text):
    sa = load_module()
    an = sa.Anonymizer(sa.build_rules([]))
    assert sa.pseudo("EMAIL", "priya.sharma@acmeholdings.com") in an.scrub_str(text)


@pytest.mark.parametrize("text", ["see section 4.2 (at) page 7", "version 1.2 at build 3.4"])
def test_email_lookalikes_untouched(text):
    sa = load_module()
    assert sa.Anonymizer(sa.build_rules([])).scrub_str(text) == text


@pytest.mark.parametrize("header,cat", [
    ("Issue key", "ISSUEKEY"), ("Issue id", "ISSUEID"), ("Assignee", "USER"), ("Assignee Id", "USERID"),
    ("Custom field (Tenant Name)", "TENANT"), ("Summary", None), ("Status", None),
    ("Custom field (Analyst Verdict)", None), ("Reporter", "USER"), ("Account Name", "USER"),
    ("userPrincipalName", "EMAIL"), ("Computer", "HOST"), ("TenantId", "TENANTID"),
    ("WorkspaceSubscriptionId", "SUBSCRIPTIONID"), ("WorkspaceResourceGroup", "RG"),
    ("SourceComputerId", "HOSTID"), ("VendorOriginalId", "VENDORID"), ("ProviderName", "PROVIDER"),
    ("VendorName", "VENDOR"), ("SourceSystem", "SYSTEM"), ("CompromisedEntity", "ENTITY"),
    ("DisplayName", None), ("AlertName", None), ("SystemAlertId", None), ("UserDisplayName", "USER")])
def test_column_classification(header, cat):
    assert load_module().column_category(header) == cat


def test_delimiter_detection():
    import io
    sa = load_module()
    for delim, text in [(",", "a; b; c"), (";", "a, b, c"), (",", "x\ty | z")]:
        buf = io.StringIO()
        w = csv.writer(buf, delimiter=delim)
        w.writerow(["Issue key", "Assignee", "Description"])
        for i in range(40):
            w.writerow([f"K-{i}", "Someone", f"{text}\nmore {text}"])
        assert sa.detect_delimiter(buf.getvalue(), ".csv") == delim


def test_chunks_are_lossless_and_bounded():
    sa = load_module()
    for text in ["The analyst reviewed alert %d. " * 700, "QUJD" * 3000, "a\n" + "x" * 2500 + "\nb"]:
        parts = sa.chunks(text)
        assert "".join(parts) == text and max(map(len, parts)) <= 1000


# --------------------------------------------------------------------------- NER interplay

STUB_NER = r'''
import importlib.util, re, sys
spec = importlib.util.spec_from_file_location("sa", sys.argv[1]); sa = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sa)
class StubModel:
    def extract_entities(self, text, labels, threshold, include_confidence, max_len):
        found = [{"text": m, "confidence": 0.95} for m in
                 re.findall(r"\b[A-Z][a-z]+ [A-Z][a-z]+\b|\b[A-Z]+_[0-9a-f]{8}\b|TKT-\d{7}", text)]
        return {"entities": {"person": found}}
class StubNER(sa.NER):
    def __init__(self, *a):
        self.hits = 0; self.model = StubModel(); self.threshold, self.name_threshold = 0.4, 0.6
sa.NER = StubNER
sys.argv = ["soc_anonymize.py"] + sys.argv[2:]
sa.main()
'''


def test_ner_never_retokenizes_tokens(tmp_path):
    fixtures.build_sentinel(tmp_path)
    fixtures.build_jira(tmp_path)
    (tmp_path / "stub.py").write_text(STUB_NER)
    r = subprocess.run([sys.executable, "stub.py", str(SCRIPT), "SecurityAlert.csv", "jira_export.csv",
                        "-o", "out", "--map", "out/map.json", "--no-progress"],
                       cwd=tmp_path, env=ENV, capture_output=True, text=True, timeout=300)
    assert r.returncode == 0, r.stdout + r.stderr
    assert_mapping_sane(json.load(open(tmp_path / "out" / "map.json")))


# --------------------------------------------------------------------------- CLI behaviour

def test_outdir_inside_input_refused(tmp_path):
    fixtures.build_multi(tmp_path / "multi")
    r = run(["multi", "-o", "multi/anon", "--no-ner"], tmp_path, check=False)
    assert r.returncode != 0 and "inside the input folder" in (r.stdout + r.stderr)
    assert not (tmp_path / "multi" / "anon").exists()


def test_folder_recursion_mirrors_structure(tmp_path):
    d = tmp_path / "exports"
    (d / "sub" / "deeper").mkdir(parents=True)
    (d / ".git").mkdir()
    fixtures.write_csv(d / "top.csv", ["Assignee", "Note"], [["Priya Sharma", "x"]])
    fixtures.write_csv(d / "sub" / "a.csv", ["Assignee", "Note"], [["Rahul Verma", "y"]])
    (d / "sub" / "deeper" / "b.json").write_text('{"value":[{"userPrincipalName":"bob@contoso.com"}]}')
    (d / ".git" / "x.csv").write_text("a\n1\n")
    (d / "sample_manifest.json").write_text("{}")
    run(["exports", "-o", "out", "--no-ner"], tmp_path)
    got = sorted(str(p.relative_to(tmp_path / "out")) for p in (tmp_path / "out").rglob("*") if p.is_file())
    assert got == ["sub/a.csv", "sub/deeper/b.json", "top.csv"]


@pytest.mark.skipif(os.name != "posix", reason="SIGINT semantics")
def test_ctrl_c_is_immediate(tmp_path):
    fixtures.write_csv(tmp_path / "rows.csv", ["Assignee", "Description"],
                       [[f"user{i}", f"Long description text number {i} about an incident"] for i in range(5)])
    slow = STUB_NER.replace(
        "class StubModel:",
        "import hashlib\nclass StubModel:").replace(
        "        found = [",
        "        hashlib.pbkdf2_hmac('sha256', b'x', b'y', 30_000_000)  # stuck in C like a torch call\n"
        "        found = [")
    (tmp_path / "slow.py").write_text(slow)
    p = subprocess.Popen([sys.executable, "slow.py", str(SCRIPT), "rows.csv", "-o", "out", "--no-progress"],
                         cwd=tmp_path, env=ENV, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    time.sleep(4)
    t0 = time.monotonic()
    p.send_signal(signal.SIGINT)
    out, _ = p.communicate(timeout=30)
    assert p.returncode == 130, out
    assert time.monotonic() - t0 < 1.0, "Ctrl-C took too long"
    assert not (tmp_path / "out" / "rows.csv").exists(), "partial output left behind"


def test_xlsx_control_characters(tmp_path):
    """calamine (fast path) decodes _x0000_ to a raw control char openpyxl can't write."""
    src = fixtures.build_control_chars_xlsx(tmp_path)
    run([src.name, "-o", "out", "--no-ner", "--xlsx-full-max-mb", "0"], tmp_path)
    from openpyxl import load_workbook
    ws = load_workbook(tmp_path / "out" / "ctrl.xlsx").active
    assert ws.max_row == 11
    assert "\ufffd" in ws["B2"].value


# --------------------------------------------------------------------------- Wazuh / AWS

def test_wazuh_fields_hosts_with_ips_and_aws(tmp_path):
    fixtures.build_wazuh(tmp_path / "wz")
    run(["wz", "-o", "out", "--no-ner", "--map", "out/map.json"], tmp_path)
    m = json.load(open(tmp_path / "out" / "map.json"))
    assert_mapping_sane(m)
    text = all_text(tmp_path / "out")
    left = [s for s in fixtures.WZ_SECRETS if s.lower() in text.lower()]
    assert not left, f"leaked: {left}"

    H, row = (r := read_csv(tmp_path / "out" / "wazuh.csv"))[0], r[1]
    col = lambda name: row[H.index(name)]
    # host names that embed an IP: one HOST token, in its column and in full_log
    host = col("_source.agent.name")
    assert host.startswith("HOST_") and col("_source.predecoder.hostname") == host
    assert host in col("_source.full_log")
    assert col("_source.manager.name").startswith("HOST_")
    # same IP -> same token in srcip, full_log and the dashed host name's own IP stays hidden
    assert col("_source.data.srcip") in col("_source.full_log")
    assert col("_source.data.aws.sourceIPAddress").startswith("HOST_")
    # public AWS service endpoints / principals kept, IP-bearing public DNS replaced
    assert col("_source.data.aws.eventSource") == "ec2.amazonaws.com"
    assert col("_source.data.aws.userIdentity.invokedBy") == "AWS Internal"
    assert col("_source.data.aws.resource.instanceDetails.networkInterfaces.publicDnsName").startswith("HOST_")
    # account id: one token in its column, the ARN and the S3 log path; ARN structure kept
    acct = col("_source.data.aws.userIdentity.accountId")
    assert acct.startswith("AWSACCOUNT_")
    assert col("_source.data.aws.userIdentity.arn").startswith(f"arn:aws:iam::{acct}:user/USER_")
    assert col("_source.data.aws.log_info.log_file").count(acct) == 2
    assert col("_source.data.srcuser") in col("_source.data.aws.userIdentity.arn")
    assert col("_source.data.aws.userIdentity.accessKeyId").startswith("AWSKEY_")
    assert col("_source.data.aws.responseElements.securityGroupRuleSet.items.securityGroupRuleId").startswith("AWSRES_")
    assert col("_source.data.aws.resource.instanceDetails.networkInterfaces.ipv6Addresses").startswith("2001:db8::")
    tags = json.loads(col("_source.data.aws.resource.instanceDetails.tags"))
    assert tags[0]["key"] == "Name" and tags[0]["value"].startswith("AWSTAG_")
    for g in ("city_name", "region_name", "country_name"):
        assert col(f"_source.GeoLocation.{g}").startswith("GEO_")
    # non-identity fields unchanged
    assert col("_source.rule.mail") == "false" and col("_source.rule.level") == "5"
    assert col("_source.rule.description") == "sshd: authentication success."
    assert col("_source.location") == "/var/log/secure"

    # nested JSON export: same tokens as the CSV, raw CloudTrail inside full_log scrubbed too
    hit = json.loads((tmp_path / "out" / "wazuh.ndjson").read_text())
    src = hit["_source"]
    assert src["manager"]["name"].startswith("HOST_") and src["rule"]["mail"] is False
    assert src["GeoLocation"]["city_name"] == col("_source.GeoLocation.city_name")
    aws = src["data"]["aws"]
    assert aws["userIdentity"]["accountId"] == acct == aws["recipientAccountId"]
    assert aws["log_info"]["s3bucket"] == col("_source.data.aws.log_info.s3bucket")
    assert aws["resource"]["instanceDetails"]["networkInterfaces"][0]["privateDnsName"] == host
    ct = json.loads(src["full_log"])
    assert ct["userIdentity"]["arn"] == aws["userIdentity"]["arn"]
    # role name is also sessionIssuer.userName -> its USER token, also inside the ARN
    role = ct["userIdentity"]["sessionContext"]["sessionIssuer"]["userName"]
    assert ct["userIdentity"]["arn"].startswith(f"arn:aws:sts::{acct}:assumed-role/{role}/USER_")
    assert ct["userIdentity"]["sessionContext"]["sessionIssuer"]["arn"] == f"arn:aws:iam::{acct}:role/{role}"
    assert ct["eventSource"] == "ec2.amazonaws.com" and ct["eventName"] == "AuthorizeSecurityGroupIngress"


@pytest.mark.parametrize("header,cat", [
    ("_source.agent.name", "HOST"), ("_source.manager.name", "HOST"), ("_source.predecoder.hostname", "HOST"),
    ("_source.data.srcuser", "USER"), ("_source.data.dstuser", "USER"), ("_source.rule.mail", None),
    ("_source.rule.description", None), ("_source.agent.id", None), ("_source.full_log", None),
    ("_source.data.win.eventdata.targetUserName", "USER"), ("_source.data.win.system.computer", "HOST"),
    ("_source.data.aws.userIdentity.accountId", "AWSACCOUNT"), ("_source.GeoLocation.city_name", "GEO"),
    ("_source.data.aws.userIdentity.sessionContext.sessionIssuer.principalId", "USERID"),
    ("_source.data.aws.resource.instanceDetails.networkInterfaces.0.privateIpAddress", "HOST"),
    ("_source.data.aws.eventSource", "HOST"), ("OwnerId", "USERID"), ("Custom field (Description.)", None)])
def test_dotted_field_classification(header, cat):
    assert load_module().column_category(header) == cat


@pytest.mark.parametrize("text,gone", [
    ("conn from ip-10-1-2-3 ok", "10-1-2-3"), ("dns ip-10-1-2-3.eu-west-1.compute.internal.", "10-1-2-3"),
    ("v6 2600:1f18:aa:bb::51 seen", "2600:1f18"), ("key AKIAZZEXAMPLE7QK3WPL used", "AKIAZZ"),
    ("arn:aws:s3:::acme-bucket/priv/x.txt", "acme-bucket")])
def test_aws_and_dashed_ip_rules(text, gone):
    sa = load_module()
    assert gone not in sa.Anonymizer(sa.build_rules([])).scrub_str(text)


@pytest.mark.parametrize("text", ["at 10:30:45 build 1.2.3", "arn:aws:iam::aws:policy/AdministratorAccess",
                                  "std::vector size 12:34", "event 4624 port 443"])
def test_aws_rules_leave_lookalikes(text):
    sa = load_module()
    assert sa.Anonymizer(sa.build_rules([])).scrub_str(text) == text
