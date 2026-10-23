# soc-anonymizer

Local, offline anonymization of SOC exports (Jira, Sentinel/Defender, SIEM, Azure logs) –
CSV/TSV, JSON/NDJSON, JSON-in-cells, XLSX, logs. Deterministic pseudonyms keep correlations:
the same user, tenant, host or ticket gets the same token everywhere.

## Quick start

```bash
uv run soc_anonymize.py --prefetch               # one-time NER model download (no data sent)
export HF_HUB_OFFLINE=1
export ANON_KEY="$(openssl rand -hex 32)"        # keep it secret and stable across runs

# try on a sample first
uv run sample_files.py ~/work/SoC -o ~/work/SoC-samples -p 10
uv run soc_anonymize.py ~/work/SoC-samples -o ~/work/SoC-anon-test --domains acme.local --map ~/work/SoC/.private/mapping.json

# full run (optionally with the LM Studio reviewer)
uv run soc_anonymize.py ~/work/SoC -o ~/work/SoC-anonymized --domains acme.local \
    --review --review-report ~/work/SoC/.private/review_report.jsonl
```

Check the `identity columns [...]` lines at the start of each run; fix misses with
`--id-columns 'Header=CATEGORY'`, `--keep-columns 'Header'` or `--terms terms.txt`.
`--map` and `--review-report` files contain the originals – keep them in `~/work/SoC/.private/`
(hidden folders are skipped as input, and Claude Code is blocked from the whole `SoC` folder).

**Run real data in your own terminal, not through Claude Code** – see `CLAUDE.md`.

## Tests

```bash
uv run --with pytest --with rich --with openpyxl --with python-calamine pytest -q tests
```
