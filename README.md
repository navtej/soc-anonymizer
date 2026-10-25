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

## Running on a cloud GPU (Ubuntu, e.g. Linode)

`setup_ubuntu_gpu.sh` prepares a fresh Ubuntu NVIDIA GPU host to run the anonymizer with the reviewer
on the node itself: NVIDIA driver, vLLM with a model (default `Qwen/Qwen3-8B-AWQ`, fits the
20 GB RTX 4000 Ada) on `127.0.0.1:1234` (the default `--review-url`; localhost only, firewall
allows SSH only), the anonymizer's dependencies, the NER model (`--prefetch`), `HF_HUB_OFFLINE=1` in root's
`~/.bashrc`, `tmux` for long runs, and `/root/soc/{in,out,.private}` (mode 700).

```bash
ssh root@<host> mkdir -p soc-anonymizer
scp setup_ubuntu_gpu.sh soc_anonymize.py sample_files.py root@<host>:soc-anonymizer/
ssh root@<host> bash soc-anonymizer/setup_ubuntu_gpu.sh   # first run: driver, reboot, run again
```

It prints the full anonymizer command at the end (`--device cuda --review --review-workers 16`).
Use the same `ANON_KEY` as on the Mac so tokens match earlier runs. Override the model with
`MODEL=... bash setup_ubuntu_gpu.sh`. The raw exports and the map sit on the instance's disk, and
cloud providers (Linode included) bill GPU instances until they are **deleted**, so copy back
`out/` and delete the instance.

## Tests

```bash
uv run --with pytest --with rich --with openpyxl --with python-calamine pytest -q tests
```
