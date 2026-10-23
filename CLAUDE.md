# SOC anonymizer

Two self-contained `uv` scripts that anonymize Security Operations exports (Jira tickets,
Microsoft Sentinel / Defender alerts, SIEM logs, Azure logs) **locally**, so the result can be
shared with LLMs and others. CSV/TSV, JSON/NDJSON, CSV/XLSX cells containing JSON, XLSX, logs.

- `soc_anonymize.py` – the anonymizer
- `sample_files.py` – makes random N% samples (default 10%) of real exports for trial runs
- `tests/` – pytest suite on **synthetic** data only (`tests/fixtures.py`)

## ⛔ Data safety – read first

The real exports live in `~/work/SoC` and contain customer PII. They must **never** reach an
LLM, and that includes you (Claude Code sends everything you read or run to the model).

- Never read, list, grep, open, sample, or `head` anything under `~/work/SoC` (raw exports; the
  `--map` / `--review-report` files live in `~/work/SoC/.private/` and contain originals) or
  `~/work/SoC-samples` (raw samples). `.claude/settings.json` denies this; don't work around it.
- Anonymized outputs (e.g. `~/work/SoC-anonymized`) may only be read when the user explicitly asks,
  e.g. to check anonymization quality - and still treat any leak you notice as sensitive: report the
  column/pattern, don't quote the value.
- Never run `soc_anonymize.py` or `sample_files.py` on real data from inside Claude Code: their
  console output (identity column names, error messages) is sent to the model. The user runs real
  data in their **own terminal**. You only ever run them on `tests/fixtures.py` data or files you
  generate in a temp dir.
- If the user pastes an error from a real run, ask for the traceback/message only, not data rows.
  If you need a reproduction, build a synthetic one in `tests/fixtures.py`.
- Never add real names, tenants, domains, GUIDs or ticket keys to code, tests, docs or commits.
  Everything in fixtures is invented (Acme Holdings, Globex, Initech, Priya Sharma, MSSOC-…).

## Conventions

- Python scripts are **self-contained uv scripts** with PEP 723 inline dependencies
  (`# /// script` header). Keep it that way; no requirements.txt / pyproject for the scripts.
  Run them with `uv run soc_anonymize.py …`.
- No new heavy dependencies without a reason. Current: `gliner2[local]`, `openpyxl`,
  `python-calamine`, `rich`.
- Tests: `uv run --with pytest --with rich --with openpyxl --with python-calamine pytest -q tests`
  (≈10 s; they use `--no-ner` and a stub model, so no model download). Run them after every change
  and add a test for every bug fixed.

## How soc_anonymize.py works

1. **Collect jobs**: files and folders (recursive, structure mirrored into `--outdir`; hidden
   files, `sample_manifest.json`, the map/report files are skipped; outdir inside an input folder
   is refused).
2. **Pre-scan** every input before writing anything: values of *identity columns* go into a
   `Lexicon` together with variants (tenant short names `Acme`/`ACME`/`AcmeHoldings`, unique
   first/last names, Jira project key prefixes, internal domains + their bare label, e-mail local
   parts). JSON inside cells and Sentinel entity objects are scanned too.
3. **Per string value** (`Anonymizer.scrub_str`):
   1. string is JSON → parse, walk (keys scrubbed too), re-serialize compactly
   2. identity column → pseudonymize the whole value (`pseudo_field`)
   3. free text → **email rules first** (plain, `%40`, `[@]`/`[.]`, `(at)`/`(dot)`) →
      **lexicon** (same token as the column) → other regex rules (IPs, GUIDs, SIDs, MACs, user
      paths, `DOMAIN\user`, JWT/secrets, Azure resource paths, `DC=`, `*.onmicrosoft.com`,
      AWS ARNs (account + names tokenized, structure kept), AWS account ids in `AWSLogs/` paths,
      access key ids, resource ids (`i-`, `sg-`, `sgr-` …), host names embedding an IP
      (`ip-10-0-3-184`), internal FQDNs from `--domains`) → GLiNER2-PII NER on prose chunks → optional LLM reviewer.
4. **Tokens** are deterministic: `HMAC(ANON_KEY, CATEGORY:value.lower())`, so the same value gets
   the same token across files and runs (`USER_1a2b3c4d`, `TENANT_…`, `TKT-1234567`,
   `user_1a2b3c4d@example.com`, IPs in 198.18.0.0/15, `2001:db8::…`). `--map` writes token → original.

### Column classification
`norm_header()` turns `Custom field (Tenant Name)` → `tenant name`, `userPrincipalName` →
`user principal name`; `COLUMN_RULES` (ordered regexes, first full match wins) assign categories.
Dotted names (Wazuh/Elastic `_source.agent.name` headers, or the same nesting in JSON – the walker
tracks the key path) are looked up in `FIELD_PATHS` (longest lowercase path suffix wins, `None` = keep,
e.g. `rule.mail`), else `COLUMN_RULES` on the last segment. HOST values that are IPs get the IP token;
public AWS endpoints (`ec2.amazonaws.com`, `AWS Internal`) fall through to free text.
SentinelOne: snake_case `account_name`/`site_name` (and `agentRealtimeInfo.accountName`) are the
customer → TENANT; a value seen as a tenant anywhere keeps the TENANT token under a generic `accountName`.
E-mail columns holding several addresses or display names (`Doe, John <j@x>`) go through free text
(each address + display name tokenized; prescan learns them). JSON that doesn't parse (cut off at
Excel's 32,767-char limit) still gets its `"key": "value"` identity fields via `KV_RX`. Internal
domains learnt in the prescan (UPN suffixes, agent domains, mail domains matching a tenant name)
feed the FQDN host rule, not only `--domains`.
`COLUMN_ONLY` categories (PROVIDER, VENDOR, SYSTEM, VENDORID, ISSUEID, GEO, AWSTAG, SERIAL) are replaced in their column
but not chased through free text. Sentinel entity objects (`{"Type": "account", "Name": …}`) use
`ENTITY_FIELDS` per entity type. Users can override with `--id-columns 'Header=CAT'`,
`--keep-columns 'Header'`, extra names with `--terms file`.

### Invariants – tests enforce these, keep them true
- **One original → exactly one token**, in every column, JSON field, file and format.
- **Never re-anonymize a token** (`apply_rules` skips values in `MAPPING`/`TOKEN_RX`; HOST rule keeps
  `HOST_x` from `HOST_x.corp.local`). Order matters: emails → lexicon → other rules.
- **Weak lexicon variants** (single-word derived names: first names, tenant short names) only match
  when Capitalised/UPPER, so "global admin" survives a tenant called "Global Bank".
- Columns that aren't identity columns (status, severity, dates, scores, tactics, alert titles)
  come out unchanged. A bare `DisplayName` is **not** a user column (Sentinel alert title).
- Bare numbers are never chased through prose (ports/counts/event IDs survive).
- Look-alike attacker domains (IOCs) are not added as internal domains.

### Robustness features (don't regress)
- **Streaming, never whole files**: CSV/TSV rows, log lines, NDJSON records and the records of a
  JSON document (top-level array, or arrays under a top-level object like Azure `{"value": [...]}`)
  are read, scrubbed and written one at a time. `JsonStream` is a small stdlib pull parser
  (`raw_decode` per element); output keeps the `json.dumps(indent=2)` layout. Progress for text
  files follows bytes read. A failed file's partial output is removed.
- **Ctrl-C is immediate**: work runs in a worker thread (`run_cancellable`); main thread waits,
  on Ctrl-C removes the half-written output, flushes reports/map, exits 130.
- **NER input is bounded**: `chunks()` splits ≤1000 chars (also inside long single lines),
  `max_len=384`, blob-like text (base64/hex) skips NER. Unbounded input once stalled a run.
- **Large XLSX**: decided by *uncompressed sheet XML size* (`xlsx_sheet_mb`, default 40 MB):
  small → full-fidelity openpyxl (formatting, comments, links, formulas' string literals, metadata
  scrubbed, pivot caches dropped); large → `xlsx_stream` (rows of one sheet at a time) +
  write-only, values only. `xlsx_stream` reads with calamine `iter_rows()` (~10x faster than
  openpyxl; holds the sheet being read, about its XML size); books over `CALAMINE_MAX_MB`
  (1000) fall back to openpyxl read-only (flat memory). calamine skips empty leading columns
  (padded back from `sheet.start`). `_xHHHH_` escapes (e.g. `_x000D_`) are decoded before
  scrubbing. Trailing rows that only carry formatting are dropped (sheets formatted to row
  1,048,576). The prescan streams XLSX the same way.
- **scrub_str memo**: results for values ≤512 chars are cached per (value, column, path),
  cleared at 50k entries. Repeated cells (status, tenant, alert title) are scrubbed once.
- **Delimiter detection** by parse consistency (`detect_delimiter`), not `csv.Sniffer`; line
  endings and BOM preserved.
- Library noise suppressed (`quiet_ml_libs`, `--verbose` to see it); rich progress bars.

### Optional components
- NER model: `fastino/gliner2-privacy-filter-PII-multi` (GLiNER2-PII, Apache-2.0). One-time
  `uv run soc_anonymize.py --prefetch`, then `HF_HUB_OFFLINE=1`. Name labels use a stricter
  threshold (`--name-threshold 0.6`).
- LLM reviewer: `--review` against LM Studio (`http://127.0.0.1:1234/v1`, Qwen 3.5 9B MLX 4-bit
  on the user's 16 GB M2). It only *flags* spans that literally occur; `--review-apply` replaces
  them. Non-localhost URLs need `--allow-remote-review`.

## sample_files.py
Exact `ceil(N·p%)` random records per file/sheet (`-p`, default 10), `--seed` for reproducibility
(per-file RNG from seed + path), `--min-rows/--max-rows`, folders recursive, `.gz` input,
`sample_manifest.json`. JSON: samples the largest array (Azure `value`, Elastic `hits.hits`) and
fixes `count`-style fields. Every format is streamed in two passes (count, then write the picks),
JSON included. XLSX: same full/streamed split as above. Same Ctrl-C handling.

## Known gaps / ideas (not done yet)
- Anonymizer can't read `.gz` directly (sampler can).
- Loose usernames in prose (`j.doe`) are only caught by NER/reviewer or `--terms`.
- E-mail tokens and account-name tokens for the same person differ (`user_x@example.com` vs
  `USER_y` for `priya.sharma`).
- Numeric XLSX cells (phone numbers typed as numbers) are not scrubbed.
- The NER model and the LM Studio reviewer have only been tested with stubs/mocks here; real
  quality on the user's data is unverified.
