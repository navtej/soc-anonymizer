"""Synthetic test data (no real customer data, ever).

Every name, tenant, domain, GUID and key below is invented. Tests build these
files into a temp folder; nothing here should be replaced with real exports.
"""
import csv
import gzip
import json
from pathlib import Path

ANALYSTS = [("Priya Sharma", "712020:5c1e8f2a-9b3d-4e61-a0f7-2d8c4b6e1a90"),
            ("Rahul Verma", "5b10a2844c20165700ede21g"),
            ("Anita Desai", "712020:aa11bb22-cc33-dd44-ee55-ff6677889900")]
TENANTS = ["Acme Holdings Pvt Ltd", "Globex Corporation", "Initech Inc"]

# Strings that must never survive anonymization (case-insensitive substring check).
JIRA_SECRETS = ["Priya", "Sharma", "Rahul", "Verma", "Anita", "Desai", "Acme", "Globex", "Initech",
                "MSSOC", "712020", "5b10a284"]
SENTINEL_SECRETS = ["priya", "rahul", "acmeholdings", "ACME-LT", "72f988bf", "3f2a1b4c", "rg-acme",
                    "law-acme", "aaaabbbb", "9a8b7c6d", "a1b2c3d4", "S-1-5-21", "ASI Scheduled"]

JIRA_HEADERS = [
    "Issue Type", "Issue key", "Issue id", "Summary", "Assignee", "Assignee Id", "Status",
    "Custom field (Time to Acknowledge)", "Custom field (Time to Respond)", "Created", "Updated",
    "Custom field (Tenant Name)", "Custom field (Analyst Verdict)", "Custom field (Severity)",
    "Custom field (Request Type)", "Custom field (Risk Score)", "Custom field (Threat Category)",
    "Custom field (Analysis and Impact(QC))", "Custom field (Analyst Verdict(QC))", "Custom field (Comments(QC))",
    "Custom field (Description(QC))", "Custom field (SOC Recommendations(QC))", "Custom field (Severity(QC))",
    "Custom field (Threat Category(QC))", "Custom field (Threat Title(QC))", "Custom field (Top Level Category(QC))",
    "Custom field (Triage Evidence(QC))", "Custom field (Risk Score (QC))", "Custom field (Threat Title)",
    "Custom field (Description.)", "Custom field (Analysis and Impact)", "Custom field (SOC Recommendations)"]

SENTINEL_HEADERS = [
    "TenantId", "TimeGenerated [UTC]", "DisplayName", "AlertName", "AlertSeverity", "Description", "ProviderName",
    "VendorName", "VendorOriginalId", "SystemAlertId", "ResourceId", "SourceComputerId", "AlertType",
    "ConfidenceLevel", "ConfidenceScore", "IsIncident", "StartTime [UTC]", "EndTime [UTC]",
    "ProcessingEndTime [UTC]", "RemediationSteps", "ExtendedProperties", "Entities", "SourceSystem",
    "WorkspaceSubscriptionId", "WorkspaceResourceGroup", "ExtendedLinks", "ProductName", "ProductComponentName",
    "AlertLink", "Status", "CompromisedEntity", "Tactics", "Techniques", "SubTechniques", "Type", "RuleQuery"]

TEN = "72f988bf-86f1-41af-91ab-2d7cd011db47"
SUB = "3f2a1b4c-5d6e-4f70-8a9b-0c1d2e3f4a5b"
RG = "rg-acme-sentinel-prod"


def jira_rows(n=30):
    rows = []
    for i in range(n):
        a, aid = ANALYSTS[i % 3]
        t = TENANTS[i % 3]
        key, short = f"MSSOC-{1200 + i}", t.split()[0]
        rows.append([
            "Incident", key, str(30100 + i),
            f"[{short}] Suspicious sign-in for j.doe@{short.lower()}.com - {a.split()[0]} triaging",
            a, aid, "Closed", "00:12", "01:30", "2026-09-01 10:00", "2026-09-02 11:00", t, "True Positive", "High",
            "Alert", "78", "Credential Access", f"Impact: {t} user account at risk; {a} confirmed MFA fatigue", "TP",
            f"QC ok; reviewed by {ANALYSTS[(i + 1) % 3][0]}", f"Login from 185.220.101.{i}, user j.doe, tenant {short}",
            "Reset creds", "High", "Credential Access", "MFA fatigue", "Identity",
            f"Evidence:\n- sign-in logs for {short}\n- see {key} and MSSOC-{1100 + i}", "80", "MFA fatigue attack",
            f"Multiple MFA pushes to j.doe at {t}.\nAssigned to {a}; escalated to {ANALYSTS[(i + 2) % 3][0]}.",
            f"{a.split()[1]} notes: no lateral movement in {short.upper()} tenant",
            f"Block 185.220.101.{i}; contact {t} IT"])
    return rows


def sentinel_rows(n=6):
    rows = []
    for i in range(n):
        entities = [
            {"$id": "2", "Name": "priya.sharma", "UPNSuffix": "acmeholdings.com",
             "AadUserId": "9a8b7c6d-1111-2222-3333-444455556666",
             "Sid": "S-1-5-21-1111111111-2222222222-3333333333-1105", "IsDomainJoined": True,
             "DisplayName": "Priya Sharma", "Type": "account"},
            {"$id": "3", "HostName": f"ACME-LT-{40 + i:04d}", "DnsDomain": "corp.acmeholdings.com",
             "NetBiosName": f"ACME-LT-{40 + i:04d}", "OMSAgentID": "aaaabbbb-cccc-dddd-eeee-ffff00001111",
             "OSFamily": "Windows", "Type": "host"},
            {"$id": "4", "MailboxPrimaryAddress": "Priya.Sharma@AcmeHoldings.com", "DisplayName": "Priya Sharma",
             "Upn": "priya.sharma@acmeholdings.com", "AadId": "9a8b7c6d-1111-2222-3333-444455556666",
             "Type": "mailbox"},
            {"$id": "5", "Recipient": "priya.sharma@acmeholdings.com", "Sender": "it-support@acme-h0ldings.xyz",
             "P1Sender": "bounce@mailer.acme-h0ldings.xyz", "SenderIP": "185.220.101.7",
             "Subject": "Password expiry for Priya", "Type": "mailMessage"},
            {"$id": "6", "Address": "185.220.101.7", "Type": "ip"},
            {"$id": "7", "Url": "https://login.acme-h0ldings.xyz/?user=priya.sharma%40acmeholdings.com", "Type": "url"},
        ]
        ext = {"Alert generation status": "Full alert created", "Query Period": "05:00:00",
               "OriginalProductComponentName": "Scheduled Alerts",
               "Recipients": json.dumps(["priya.sharma@acmeholdings.com", "rahul.verma@acmeholdings.com"]),
               "rahul.verma@acmeholdings.com": "secondary recipient",
               "Account": "ACMEHOLDINGS\\priya.sharma",
               "Analytic Rule Ids": json.dumps(["e1f2a3b4-0000-1111-2222-333344445555"])}
        rid = (f"/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.OperationalInsights/"
               f"workspaces/law-acme-soc")
        rows.append([
            TEN, "2026-09-01T10:00:00Z", "Suspicious inbox forwarding rule", "Suspicious inbox forwarding rule",
            "High",
            f"User priya.sharma[@]acmeholdings[.]com created a forwarding rule on ACME-LT-{40 + i:04d}.",
            "ASI Scheduled Alerts", "Microsoft", f"a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c{50 + i}",
            f"b2c3d4e5-f6a7-4b5c-9d0e-1f2a3b4c5d{60 + i}", rid, "aaaabbbb-cccc-dddd-eeee-ffff00001111",
            f"{TEN}_e1f2a3b4", "", "", "False", "2026-09-01T09:55:00Z", "2026-09-01T10:00:00Z",
            "2026-09-01T10:01:00Z", "Contact priya.sharma@acmeholdings.com and reset credentials.",
            json.dumps(ext), json.dumps(entities), "Detection", SUB, RG,
            json.dumps([{"Href": f"https://portal.azure.com/#@acmeholdings.onmicrosoft.com/resource{rid}",
                         "Category": "Investigation"}]),
            "Azure Sentinel", "Scheduled Alerts",
            f"https://portal.azure.com/#blade/Microsoft_Azure_Security/AlertBlade/alertId/x/subscriptionId/{SUB}"
            f"/resourceGroup/{RG}/referencedFrom/alertDeepLink/location/centralindia",
            "New", "priya.sharma@acmeholdings.com", "[\"Persistence\"]", "[\"T1114\"]", "[]", "SecurityAlert",
            "OfficeActivity | where UserId =~ 'priya.sharma@acmeholdings.com' | where Operation == 'New-InboxRule'"])
    return rows


def write_csv(path, headers, rows, delimiter=","):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, delimiter=delimiter)
        w.writerow(headers)
        w.writerows(rows)
    return path


def build_jira(folder):
    return write_csv(Path(folder) / "jira_export.csv", JIRA_HEADERS, jira_rows())


def build_sentinel(folder):
    return write_csv(Path(folder) / "SecurityAlert.csv", SENTINEL_HEADERS, sentinel_rows())


def build_multi(folder):
    """Several formats that mention the same people / tenants / tickets."""
    from openpyxl import Workbook
    d = Path(folder)
    d.mkdir(parents=True, exist_ok=True)
    build_jira(d)
    (d / "siem.ndjson").write_text(
        '{"ts":"2026-09-01T10:00:00Z","message":"MFA push storm for Acme user; analyst Priya Sharma linked MSSOC-1203"}\n'
        '{"ts":"2026-09-01T10:05:00Z","message":"Globex VPN anomaly, see ticket mssoc-1201; global admin role not involved"}\n')
    (d / "azure.json").write_text(json.dumps({"value": [{"tenantName": "Initech Inc", "initiatedBy": "Anita Desai",
                                                         "activity": "Initech conditional access change by Desai"}]}))
    wb = Workbook()
    ws = wb.active
    ws.title = "Escalations"
    ws.append(["Ticket", "Owner", "Client", "Notes"])
    ws.append(["MSSOC-1205", "Rahul Verma", "Globex Corporation", "Verma escalated to GLOBEX SOC lead"])
    wb.save(d / "escalations.xlsx")
    write_csv(d / "weak.csv", ["Assignee", "Customer", "Summary"],
              [["Will Turner", "Global Bank Ltd",
                "Global Bank portal alert; global admin role reviewed; will escalate; Will checked GLOBAL logs"]])
    return d


def build_sampling_set(folder):
    """Mixed formats for sample_files.py."""
    from openpyxl import Workbook
    from openpyxl.comments import Comment
    from openpyxl.styles import Font
    d = Path(folder)
    (d / "sub").mkdir(parents=True, exist_ok=True)
    with open(d / "jira.csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["Key", "Assignee", "Description"])
        for i in range(1000):
            w.writerow([f"SOC-{i}", f"user{i}", f"line one {i}\nline two {i}"])
    write_csv(d / "semi.csv", ["a", "b"], [[i, f"x{i}"] for i in range(200)], delimiter=";")
    write_csv(d / "data.tsv", ["ip", "user"], [[f"10.0.0.{i % 255}", f"u{i}"] for i in range(500)], delimiter="\t")
    with gzip.open(d / "siem.ndjson.gz", "wt") as f:
        for i in range(2000):
            f.write(json.dumps({"i": i, "msg": f"evt {i}"}) + "\n")
    (d / "azure.json").write_text(json.dumps({"count": 300, "value": [{"i": i} for i in range(300)]}))
    (d / "elastic.json").write_text(json.dumps({"took": 5, "hits": {"total": {"value": 800},
                                                                    "hits": [{"_id": i} for i in range(800)]}}))
    wb = Workbook()
    ws = wb.active
    ws.title = "Tickets"
    ws.append(["Key", "Assignee", "Link"])
    ws["A1"].font = Font(bold=True)
    for i in range(400):
        ws.append([f"SOC-{i}", f"user{i}", "link"])
    ws["B2"].comment = Comment("note", "analyst")
    h = wb.create_sheet("Raw")
    h.sheet_state = "hidden"
    h.append(["src"])
    for i in range(37):
        h.append([f"r{i}"])
    wb.save(d / "book.xlsx")
    (d / "sub" / "app.log").write_text("\n".join(f"log line {i}" for i in range(100)) + "\n")
    (d / "legacy.xls").write_bytes(b"")
    return d


def build_control_chars_xlsx(folder):
    """Cells holding control characters: Excel stores them as _xHHHH_ escapes,
    which decode to raw chars that openpyxl refuses to write."""
    from openpyxl import Workbook
    d = Path(folder)
    d.mkdir(parents=True, exist_ok=True)
    wb = Workbook()
    ws = wb.active
    ws.append(["Account", "Notes"])
    for i in range(10):
        ws.append(["NT AU_x001E_THORITY\\SYSTEM", f"Priya_x0000_Sharma ran job {i}"])
    wb.save(d / "ctrl.xlsx")
    return d / "ctrl.xlsx"


# Wazuh alerts (Kibana/OpenSearch CSV export with flattened '_source.*' headers, and the
# same alerts as an Elasticsearch NDJSON export). Account, IPs, keys, names: all invented.
WZ_ACCT = "210987654321"
WZ_SECRETS = [WZ_ACCT, "10-20-3-184", "10.20.3.184", "10-20-7-9", "10.20.7.9", "54-210-33-7", "54.210.33.7",
              "2600:1f18:aa:bb::51", "AKIAZZEXAMPLE7QK3WPL", "ASIAZZEXAMPLE9RT4XYZ", "sgr-0a1b2c3d4e5f60718",
              "i-0f1e2d3c4b5a69788", "AcmeSocAdmin", "priya.sharma", "acme-prod-web", "acme-cloudtrail-logs",
              "wazuh-mgr-acme", "Pune", "Maharashtra", "India", "203.0.113.77"]
WZ_CLOUDTRAIL = {
    "eventVersion": "1.08", "eventSource": "ec2.amazonaws.com", "eventName": "AuthorizeSecurityGroupIngress",
    "awsRegion": "us-east-1", "sourceIPAddress": "203.0.113.77", "userAgent": "aws-cli/2.15.0 md/ip-10-20-7-9",
    "recipientAccountId": WZ_ACCT,
    "userIdentity": {"type": "AssumedRole", "principalId": "AROAZZEXAMPLE1AB2CD3:priya.sharma",
                     "arn": f"arn:aws:sts::{WZ_ACCT}:assumed-role/AcmeSocAdmin/priya.sharma",
                     "accountId": WZ_ACCT, "accessKeyId": "ASIAZZEXAMPLE9RT4XYZ",
                     "sessionContext": {"sessionIssuer": {
                         "type": "Role", "principalId": "AROAZZEXAMPLE1AB2CD3",
                         "arn": f"arn:aws:iam::{WZ_ACCT}:role/AcmeSocAdmin", "userName": "AcmeSocAdmin"}}},
    "responseElements": {"securityGroupRuleSet": {"items": [{
        "securityGroupRuleId": "sgr-0a1b2c3d4e5f60718",
        "securityGroupRuleArn": f"arn:aws:ec2:us-east-1:{WZ_ACCT}:security-group-rule/sgr-0a1b2c3d4e5f60718"}]}},
}
WZ_HEADERS = [
    "_id", "_source.timestamp", "_source.rule.level", "_source.rule.description", "_source.rule.mail",
    "_source.agent.id", "_source.agent.name", "_source.agent.ip", "_source.manager.name",
    "_source.predecoder.hostname", "_source.location", "_source.full_log", "_source.data.srcuser",
    "_source.data.dstuser", "_source.data.srcip", "_source.data.command", "_source.data.pwd",
    "_source.data.aws.eventSource", "_source.data.aws.sourceIPAddress", "_source.data.aws.log_info.log_file",
    "_source.data.aws.log_info.s3bucket", "_source.data.aws.userIdentity.accessKeyId",
    "_source.data.aws.userIdentity.accountId", "_source.data.aws.userIdentity.arn",
    "_source.data.aws.userIdentity.invokedBy",
    "_source.data.aws.userIdentity.sessionContext.sessionIssuer.principalId",
    "_source.data.aws.resource.instanceDetails.networkInterfaces",
    "_source.data.aws.resource.instanceDetails.networkInterfaces.privateDnsName",
    "_source.data.aws.resource.instanceDetails.networkInterfaces.publicDnsName",
    "_source.data.aws.resource.instanceDetails.networkInterfaces.ipv6Addresses",
    "_source.data.aws.resource.instanceDetails.tags",
    "_source.data.aws.responseElements.securityGroupRuleSet.items.securityGroupRuleId",
    "_source.GeoLocation.city_name", "_source.GeoLocation.region_name", "_source.GeoLocation.country_name",
]
WZ_ROW = [
    "wz-1", "2026-09-01T10:00:00.000+0000", "5", "sshd: authentication success.", "false",
    "007", "ip-10-20-3-184", "10.20.3.184", "wazuh-mgr-acme",
    "ip-10-20-3-184", "/var/log/secure",
    "Sep  1 10:00:00 ip-10-20-3-184 sshd[4242]: Accepted publickey for priya.sharma from 10.20.7.9 port 51122",
    "priya.sharma", "root", "10.20.7.9", "sudo cat /home/priya.sharma/.aws/credentials", "/home/priya.sharma",
    "ec2.amazonaws.com", "ip-10-20-7-9.ec2.internal",
    f"AWSLogs/{WZ_ACCT}/CloudTrail/us-east-1/2026/09/01/{WZ_ACCT}_CloudTrail_us-east-1_20260901T1000Z_x1.json.gz",
    "acme-cloudtrail-logs", "AKIAZZEXAMPLE7QK3WPL", WZ_ACCT,
    f"arn:aws:iam::{WZ_ACCT}:user/priya.sharma", "AWS Internal", "AROAZZEXAMPLE1AB2CD3",
    json.dumps([{"privateDnsName": "ip-10-20-3-184.ec2.internal", "privateIpAddress": "10.20.3.184",
                 "publicIp": "54.210.33.7", "subnetId": "subnet-0abc1234def567890"}]),
    "ip-10-20-3-184.ec2.internal", "ec2-54-210-33-7.compute-1.amazonaws.com", "2600:1f18:aa:bb::51",
    json.dumps([{"key": "Name", "value": "acme-prod-web"}]), "sgr-0a1b2c3d4e5f60718",
    "Pune", "Maharashtra", "India",
]


def build_wazuh(folder):
    d = Path(folder)
    d.mkdir(parents=True, exist_ok=True)
    write_csv(d / "wazuh.csv", WZ_HEADERS, [WZ_ROW])
    hit = {"_index": "wazuh-alerts-4.x-2026.09.01", "_id": "wz-2", "_source": {
        "rule": {"level": 3, "description": "AWS CloudTrail: ec2 AuthorizeSecurityGroupIngress", "mail": False},
        "agent": {"id": "000", "name": "wazuh-mgr-acme"}, "manager": {"name": "wazuh-mgr-acme"},
        "location": "aws-s3", "full_log": json.dumps(WZ_CLOUDTRAIL),
        "GeoLocation": {"city_name": "Pune", "country_name": "India", "location": {"lat": 18.5, "lon": 73.8}},
        "data": {"aws": {**WZ_CLOUDTRAIL, "source": "cloudtrail",
                         "log_info": {"s3bucket": "acme-cloudtrail-logs", "log_file": WZ_ROW[19]},
                         "resource": {"instanceDetails": {
                             "instanceId": "i-0f1e2d3c4b5a69788",
                             "networkInterfaces": [{"privateDnsName": "ip-10-20-3-184.ec2.internal",
                                                    "ipv6Addresses": ["2600:1f18:aa:bb::51"]}],
                             "tags": [{"key": "Name", "value": "acme-prod-web"}]}}}}}}
    (d / "wazuh.ndjson").write_text(json.dumps(hit) + "\n")
    return d


def build_streaming_set(folder):
    """Files for the streaming code paths: a JSON document with many records, a
    top-level JSON array, JSON lines saved as .json, and a workbook with CRLF
    escapes and formatting that runs far below the data."""
    from openpyxl import Workbook
    from openpyxl.styles import Font
    d = Path(folder)
    d.mkdir(parents=True, exist_ok=True)
    recs = [{"userPrincipalName": "priya.sharma@acmeholdings.com", "tenantName": "Acme Holdings Pvt Ltd",
             "message": f"Sign-in {i} from 10.20.30.{i % 250} for priya.sharma@acmeholdings.com",
             "score": i / 7, "ok": i % 2 == 0, "tags": [], "extra": {}} for i in range(1500)]
    (d / "azure.json").write_text(json.dumps({"@odata.context": "https://graph.example.test/$metadata",
                                              "count": len(recs), "value": recs, "nextLink": None}))
    (d / "array.json").write_text(json.dumps(recs[:50], indent=4))
    (d / "lines.json").write_text("".join(json.dumps(r) + "\n" for r in recs[:20]))
    wb = Workbook()
    ws = wb.active
    ws.title = "Alerts"
    ws.append(["Account", "Notes"])
    for i in range(30):
        ws.append(["Priya Sharma", f"Login from 10.1.2.{i}_x000D_\nchecked by SOC"])
    ws.cell(row=5000, column=1).font = Font(bold=True)         # formatting only, no value
    h = wb.create_sheet("Raw")
    h.sheet_state = "hidden"
    h.append(["src"])
    h.append(["192.168.7.7"])
    wb.save(d / "alerts.xlsx")
    return d


# SentinelOne alerts exported to XLSX (snake_case columns; alert_json / original_raw_payload hold
# JSON, sometimes cut off at Excel's 32,767-char cell limit, and raw e-mail messages).
S1_SECRETS = ["Acme Holdings", "AcmeHoldings", "acmeholdings", "priya.sharma", "Priya Sharma", "Sharma, Priya",
              "rahul.verma", "Rahul Verma", "anita.desai", "Anita Desai", "ACME-LT-0042", "10.20.5.17",
              "billing.globex"]
S1_ALERT = {
    "alertInfo": {"name": "Suspicious e-mail link clicked", "severity": "High", "analystVerdict": "undefined"},
    "agentRealtimeInfo": {"accountName": "Acme Holdings", "siteName": "Acme Holdings - Pune",
                          "agentComputerName": "ACME-LT-0042", "agentDomain": "corp.acmeholdings.com",
                          "agentLastLoggedInUserName": "priya.sharma"},
    "agentDetectionInfo": {"agentIpV4": "10.20.5.17", "agentLastLoggedInUpn": "priya.sharma@acmeholdings.com"},
    "email": {"recipients": ["priya.sharma@acmeholdings.com", "rahul.verma@acmeholdings.com"],
              "senderDisplayName": "Anita Desai", "from": "\"Desai, Anita\" <anita.desai@acmeholdings.com>"},
}
S1_RAW_MAIL = ("Received: from mail.acmeholdings.com (10.20.5.17) by mx.example.net\r\n"
               "From: \"Sharma, Priya\" <priya.sharma@acmeholdings.com>\r\n"
               "To: Rahul Verma <rahul.verma@acmeholdings.com>, billing.globex&#64;globex.example\r\n"
               "Subject: Invoice overdue\r\n\r\nHi Rahul, see attached. Priya")


def build_sentinelone_xlsx(folder):
    from openpyxl import Workbook
    d = Path(folder)
    d.mkdir(parents=True, exist_ok=True)
    payload = json.dumps({"event": {"raw": S1_RAW_MAIL, "accountName": "Acme Holdings",
                                    "user": "priya.sharma", "padding": "x" * 200}})
    wb = Workbook()
    ws = wb.active
    ws.append(["alert_id", "severity", "account_name", "recipient_address", "alert_json", "original_raw_payload"])
    ws.append(["s1-1", "High", "Acme Holdings", "priya.sharma@acmeholdings.com; rahul.verma@acmeholdings.com",
               json.dumps(S1_ALERT), payload])
    ws.append(["s1-2", "Medium", "Acme Holdings", "Rahul Verma <rahul.verma@acmeholdings.com>",
               json.dumps(S1_ALERT)[:-40], payload[:-60]])        # cut off like Excel's cell limit
    ws.append(["s1-3", "Low", "Acme Holdings", "anita.desai@acmeholdings.com", S1_RAW_MAIL,
               "mail from priya.sharma\\u0040acmeholdings.com\\nrahul.verma@acmeholdings.com"])
    wb.save(d / "s1_alerts.xlsx")
    return d
