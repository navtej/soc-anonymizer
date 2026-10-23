"""Regression tests for soc_anonymize.py - synthetic data only, rules mode (no NER download).

Run:  uv run --with pytest --with rich --with openpyxl pytest -q tests
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
    """The streamed path decodes _x0000_ to a raw control char openpyxl can't write."""
    src = fixtures.build_control_chars_xlsx(tmp_path)
    run([src.name, "-o", "out", "--no-ner", "--xlsx-full-max-mb", "0"], tmp_path)
    from openpyxl import load_workbook
    ws = load_workbook(tmp_path / "out" / "ctrl.xlsx").active
    assert ws.max_row == 11
    assert "\ufffd" in ws["B2"].value


# --------------------------------------------------------------------------- streaming

def test_json_document_streamed_record_by_record(tmp_path):
    fixtures.build_streaming_set(tmp_path / "in")
    run(["in/azure.json", "in/array.json", "-o", "out", "--no-ner", "--map", "out/map.json"], tmp_path)
    assert_mapping_sane(json.load(open(tmp_path / "out" / "map.json")))
    for name, n in [("azure.json", 1500), ("array.json", 50)]:
        text = (tmp_path / "out" / name).read_text(encoding="utf-8")
        data = json.loads(text)
        assert text == json.dumps(data, ensure_ascii=False, indent=2), "layout differs from a whole dump"
        recs = data["value"] if name == "azure.json" else data
        assert len(recs) == n
        assert len({r["userPrincipalName"] for r in recs}) == 1          # one token for one original
        assert all(r["tags"] == [] and r["extra"] == {} and isinstance(r["ok"], bool) for r in recs)
        assert not any(s in text.lower() for s in ("priya", "acme", "10.20.30.")), name
    az = json.loads((tmp_path / "out" / "azure.json").read_text())
    assert list(az) == ["@odata.context", "count", "value", "nextLink"] and az["count"] == 1500
    assert az["nextLink"] is None


def test_ndjson_saved_as_json(tmp_path):
    fixtures.build_streaming_set(tmp_path / "in")
    run(["in/lines.json", "-o", "out", "--no-ner"], tmp_path)
    lines = (tmp_path / "out" / "lines.json").read_text().splitlines()
    assert len(lines) == 20 and all(json.loads(l)["userPrincipalName"].endswith("@example.com") for l in lines)


@pytest.mark.parametrize("script", ["soc_anonymize.py", "sample_files.py"])
def test_json_stream_parses_exactly_with_bounded_buffer(script):
    import io
    spec = importlib.util.spec_from_file_location(script[:-3], ROOT / script)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    tricky = [12345678901234567890, -0.5e-7, "quote \" and \\ and \u00e9 \ud83d\ude00", None, True,
              {"a": [1, {"b": []}], "": {}}, [], "x" * 50, 1e308, "\u2028 line sep"]
    doc = json.dumps({"head": 1, "value": tricky * 300, "tail": "end"}, ensure_ascii=False)
    for chunk in (1, 3, 7, 64):
        js = mod.JsonStream(io.StringIO(doc), chunk=chunk)
        got, peak, rest = [], 0, {}
        for k in js.keys():
            if js.peek() == "[":
                for _ in js.elements():
                    got.append(js.value())
                    peak = max(peak, len(js.buf))
            else:
                rest[k] = js.value()
        js.finish()
        assert got == tricky * 300 and rest == {"head": 1, "tail": "end"}, chunk
        assert peak <= 4 * max(chunk, 64), f"buffer grew to {peak} - not streaming"
    for bad in ('{"a": 1} {"b": 2}', '[1, 2', '[1 2]', '{"a" 1}'):     # extra data, cut off, broken
        js = mod.JsonStream(io.StringIO(bad), chunk=2)
        with pytest.raises(ValueError):
            if js.peek() == "[":
                for _ in js.elements():
                    js.value()
            else:
                for _ in js.keys():
                    js.value()
            js.finish()


def test_xlsx_streamed_path(tmp_path):
    """Large-book path: rows streamed, CRLF escapes decoded before the rules run,
    formatting-only rows below the data dropped, hidden sheets kept hidden."""
    fixtures.build_streaming_set(tmp_path / "in")
    r = run(["in/alerts.xlsx", "-o", "out", "--no-ner", "--xlsx-full-max-mb", "0"], tmp_path)
    assert "streamed" in r.stderr
    from openpyxl import load_workbook
    wb = load_workbook(tmp_path / "out" / "alerts.xlsx")
    ws, raw = wb["Alerts"], wb["Raw"]
    assert ws.max_row == 31 and raw.sheet_state == "hidden"
    assert [c.value for c in ws[1]] == ["Account", "Notes"]
    cells = [str(c.value) for s in wb.worksheets for row in s.iter_rows() for c in row if c.value]
    assert not [c for c in cells if "10.1.2." in c or "Priya" in c or "192.168.7.7" in c], cells[:5]
    assert all("checked by SOC" in str(ws.cell(row=i, column=2).value) for i in range(2, 32))


def test_xlsx_crlf_escape_does_not_hide_ips_full_path(tmp_path):
    """Excel stores CR as _x000D_; '10.1.2.0_x000D_' has no word boundary, so the IP
    rule used to miss it in the full-fidelity path."""
    fixtures.build_streaming_set(tmp_path / "in")
    run(["in/alerts.xlsx", "-o", "out", "--no-ner"], tmp_path)
    from openpyxl import load_workbook
    ws = load_workbook(tmp_path / "out" / "alerts.xlsx")["Alerts"]
    notes = [ws.cell(row=i, column=2).value for i in range(2, 32)]
    assert not [n for n in notes if "10.1.2." in n or "_x000D_" in n], notes[:3]


def test_failed_file_leaves_no_partial_output(tmp_path):
    good = "".join(json.dumps({"user": f"user{i}", "msg": "x" * 200}) + "\n" for i in range(2000))
    (tmp_path / "broken.ndjson").write_text(good + "{not json\n" + good)
    r = run(["broken.ndjson", "-o", "out", "--no-ner"], tmp_path, check=False)
    assert r.returncode == 1 and "broken.ndjson" in r.stderr
    assert not (tmp_path / "out" / "broken.ndjson").exists()
