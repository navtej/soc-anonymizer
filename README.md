# soc-anonymizer

Local, offline anonymization of Security Operations exports – Jira tickets, Microsoft
Sentinel / Defender alerts, SIEM logs (Wazuh, Elastic, SentinelOne), Azure and AWS logs – so
they can be shared with LLMs, vendors or colleagues without leaking customer data.

- **Formats**: CSV/TSV/PSV, JSON (arrays, Azure `{"value": [...]}`, Elastic hits), NDJSON/JSONL,
  plain logs, XLSX/XLSM (all sheets, incl. hidden), and JSON embedded in CSV/XLSX cells.
- **Deterministic pseudonyms**: the same user, tenant, host, IP or ticket gets the same token in
  every column, file and run (`USER_1a2b3c4d`, `TENANT_…`, `TKT-1234567`,
  `user_1a2b3c4d@example.com`, IPs in `198.18.0.0/15`), so correlations survive.
- **Layered detection**: identity columns → lexicon of their values chased through free text →
  regex rules (emails, IPs, GUIDs, SIDs, MACs, `DOMAIN\user`, secrets/JWTs, Azure resource
  paths, AWS ARNs/account ids, internal FQDNs …) → GLiNER2-PII NER on prose → optional local
  LLM reviewer.
- **Everything runs locally.** The NER model is downloaded once; the optional reviewer talks to
  a local OpenAI-compatible server (LM Studio, vLLM). Remote endpoints are refused unless you
  explicitly allow them.
- **Streams, never loads whole files**: multi-GB CSV, NDJSON, JSON and XLSX work in flat memory.

Two scripts:

| Script | Purpose |
|---|---|
| [`sample_files.py`](sample_files.py) | Make random N % samples of real exports for trial runs |
| [`soc_anonymize.py`](soc_anonymize.py) | The anonymizer |

> [!WARNING]
> Inputs, samples, the `--map` file and the `--review-report` file all contain **real data**.
> Keep them in a private folder (e.g. `~/soc/.private/`), never commit them, and don't run the
> scripts on real data from inside an AI coding agent – its console output goes to the model.

## Setup

Python ≥ 3.10. The scripts are self-contained [uv](https://docs.astral.sh/uv/) scripts (PEP 723
inline dependencies), so with uv there is nothing to install besides uv itself. A
`requirements.txt` is provided for a classic venv/pip setup.

### macOS

```bash
# 1. uv (or: brew install uv)
curl -LsSf https://astral.sh/uv/install.sh | sh

# 2. code
git clone https://github.com/navtej/soc-anonymizer.git
cd soc-anonymizer

# 3. one-time NER model download (no data is sent), then stay offline
uv run soc_anonymize.py --prefetch
echo 'export HF_HUB_OFFLINE=1' >> ~/.zshrc

# 4. a secret key for the pseudonyms – keep it private and stable across runs
openssl rand -hex 32 > ~/.soc_anon_key && chmod 600 ~/.soc_anon_key
export ANON_KEY="$(cat ~/.soc_anon_key)"
```

On Apple Silicon the NER model runs on the GPU (MPS) automatically.

### Linux (Ubuntu / Debian / Fedora …)

```bash
# 1. uv
curl -LsSf https://astral.sh/uv/install.sh | sh
source ~/.local/bin/env          # or open a new shell

# 2. code
git clone https://github.com/navtej/soc-anonymizer.git
cd soc-anonymizer

# 3. one-time NER model download, then stay offline
uv run soc_anonymize.py --prefetch
echo 'export HF_HUB_OFFLINE=1' >> ~/.bashrc

# 4. secret key
openssl rand -hex 32 > ~/.soc_anon_key && chmod 600 ~/.soc_anon_key
export ANON_KEY="$(cat ~/.soc_anon_key)"
```

With an NVIDIA GPU and CUDA-enabled PyTorch the NER model uses CUDA automatically
(`--device auto`); otherwise it runs on the CPU.

### Without uv (venv + pip)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python soc_anonymize.py --prefetch
python sample_files.py --help    # use `python` instead of `uv run` in the examples below
```

`sample_files.py` only needs `openpyxl`, `python-calamine` and `rich`; `gliner2[local]` (which
pulls in PyTorch) is only needed by the anonymizer, and not at all with `--no-ner`.

### Optional: local LLM reviewer

For a second pass that flags leftovers the rules and NER missed, run any OpenAI-compatible server
on localhost, e.g. [LM Studio](https://lmstudio.ai) (default `http://127.0.0.1:1234/v1`) with a
small instruct model such as Qwen 3.5 9B, or vLLM. See `--review` below.

## Sampling real exports – `sample_files.py`

Try the anonymizer on a small, representative slice before running it on everything.
`sample_files.py` writes an exact random `ceil(N × percent / 100)` records per file (per sheet
for XLSX), keeps headers and original order, and mirrors the folder structure into `--outdir`.

```bash
uv run sample_files.py exports/*.csv exports/*.xlsx                  # 10 % -> ./samples/
uv run sample_files.py exports/ -p 2.5 -o samples_2pct --seed 42     # whole folder, reproducible
uv run sample_files.py big_siem.ndjson.gz -p 1 --max-rows 5000
```

Supported inputs:

| Format | Sampled unit |
|---|---|
| `.csv .tsv .tab .psv` | rows (header kept, delimiter auto-detected, multi-line quoted cells handled) |
| `.ndjson .jsonl .log .txt` | non-empty lines |
| `.json` | array elements; for an object its largest array (Azure `value`, `records`, Elastic `hits.hits`), other keys kept and `count`-style fields fixed |
| `.xlsx .xlsm` | data rows of every sheet incl. hidden (`.xlsm` → `.xlsx`, macros dropped) |
| `*.gz` | any of the text formats above, gzip-compressed |

Small workbooks keep formatting, comments, links, widths and frozen panes; workbooks whose
uncompressed sheet data exceeds `--xlsx-full-max-mb` are streamed values-only.
A `sample_manifest.json` (seed, percent, per-file counts) is written next to the samples.

| Argument | Default | Description |
|---|---|---|
| `inputs …` | – | Files and/or folders (folders are walked recursively) |
| `-p`, `--percent` | `10` | Share of records to keep, 0–100 |
| `-o`, `--outdir` | `./samples` | Output folder |
| `--seed` | random (printed) | Seed for reproducible samples; each file gets its own RNG from seed + path |
| `--min-rows` | `1` | Keep at least this many records per file/sheet |
| `--max-rows` | – | Keep at most this many records per file/sheet |
| `--xlsx-full-max-mb` | `25` | Workbooks up to this uncompressed sheet size keep formatting; larger ones are streamed values-only |
| `--no-recursive` | off | Don't descend into sub-folders |
| `--no-progress` | off | Plain output, no progress bars |
| `--verbose` | off | Full tracebacks on errors |

## Anonymizing – `soc_anonymize.py`

```bash
export ANON_KEY="$(cat ~/.soc_anon_key)"
export HF_HUB_OFFLINE=1

# trial run on the samples
uv run soc_anonymize.py samples/ -o anon-test \
    --domains corp.local,acme.internal --map ~/soc/.private/mapping.json

# full run, with the local LLM reviewer applying its findings
uv run soc_anonymize.py exports/ -o anonymized/ --domains corp.local,acme.internal \
    --map ~/soc/.private/mapping.json \
    --review --review-apply --review-report ~/soc/.private/review_report.jsonl
```

### How it works

1. **Collect** files and folders (recursive; structure mirrored into `--outdir`; hidden files
   and folders are skipped, so `.private/` next to the data is safe).
2. **Pre-scan** every input: values of *identity columns* (assignee, reporter, tenant/customer,
   issue key, UPN, host, account name … – recognised from headers like
   `Custom field (Tenant Name)` or `userPrincipalName`, and from JSON key paths like
   `agent.name`) are collected into a lexicon with their variants (tenant short names, first/last
   names, Jira project prefixes, internal domains, e-mail local parts).
3. **Scrub** every string value: JSON in a cell is parsed and walked; identity columns are
   replaced whole; free text gets the e-mail rules, then the lexicon (same token as the column),
   then the other regex rules, then NER, then the optional reviewer.
4. **Tokens** are `HMAC(ANON_KEY, category:value)`, so they are stable across files and runs as
   long as you keep the same key. `--map` writes token → original for your own lookups.

Each run starts by printing the `identity columns [...]` it recognised per file – check them and
fix misses with `--id-columns`, `--keep-columns` or `--terms`. Non-identity columns (status,
severity, dates, scores, tactics, alert titles) pass through unchanged; bare numbers in prose
(ports, counts, event IDs) are kept.

### Arguments

| Argument | Default | Description |
|---|---|---|
| `files …` | – | Files and/or folders; folders are searched recursively |
| `-o`, `--outdir` | `./anonymized` | Output folder (must not be inside an input folder) |
| `--domains` | – | Internal DNS suffixes, comma-separated (`corp.local,acme.internal`); host names under them are tokenized |
| `--map` | – | Write the token → original map (**sensitive**, keep private) |
| `--no-ner` | off | Rules and lexicon only: fast, no model |
| `--model` | `fastino/gliner2-privacy-filter-PII-multi` | Hugging Face id or local directory of the GLiNER2 PII model |
| `--prefetch` | – | Download the NER model into the local cache and exit |
| `--threshold` | `0.4` | NER confidence threshold |
| `--name-threshold` | `0.6` | Stricter threshold for person/name labels |
| `--device` | `auto` | `auto` (CUDA, else Apple MPS, else CPU), `cpu`, `cuda`, `mps` |
| `--xlsx-full-max-mb` | `40` | Workbooks up to this uncompressed sheet size keep formatting, comments, links; larger ones are streamed values-only |
| `--no-recursive` | off | For folders, only take files directly inside them |
| `--no-progress` | off | Plain output, no progress bars |
| `--verbose` | off | Show library warnings and full tracebacks |

**Identity columns & lexicon**

| Argument | Description |
|---|---|
| `--terms FILE` | Extra terms to always replace, one per line, optionally `term,CATEGORY` (tenant aliases, project codenames, internal host names …) |
| `--id-columns` | Force columns as identity columns: `'Header=CATEGORY,Other Header=TENANT'` |
| `--keep-columns` | Never treat these columns as identity columns: `'Header,Other Header'` |
| `--no-lexicon` | Don't chase identity-column values through free text |

**Second pass: local LLM reviewer**

| Argument | Default | Description |
|---|---|---|
| `--review` | off | Enable the reviewer: it reads already-anonymized free text and flags spans that still identify a person or organisation (only spans that literally occur are accepted) |
| `--review-apply` | off | Pseudonymize flagged spans (without it: dry run, report only) |
| `--review-url` | `http://127.0.0.1:1234/v1` | OpenAI-compatible base URL (LM Studio default) |
| `--review-model` | first loaded model | Model id |
| `--review-report` | `review_report.jsonl` | JSONL of flagged spans (**sensitive**: contains the leaked values) |
| `--review-min-len` | `20` | Only review strings at least this long |
| `--review-workers` | `4` | Records reviewed in parallel (LLM requests in flight); match the server's concurrency |
| `--allow-remote-review` | off | Permit a non-localhost `--review-url` (private endpoint only) |

### Limitations

- The anonymizer doesn't read `.gz` directly (the sampler does) – decompress first.
- Numeric XLSX cells (e.g. a phone number typed as a number) are not scrubbed.
- Loose user names in prose (`j.doe`) are only caught by NER, the reviewer or `--terms`.
- No automated tool is perfect: spot-check the output before sharing it.

## Running on a cloud GPU (Ubuntu)

`setup_ubuntu_gpu.sh` (run as root) prepares a fresh Ubuntu NVIDIA GPU host to run the
anonymizer with the reviewer on the node itself: NVIDIA driver, vLLM serving a model (default
`Qwen/Qwen3-8B-AWQ`) on `127.0.0.1:1234`, the NER model, `HF_HUB_OFFLINE=1`, `tmux`, and
`/root/soc/{in,out,.private}` (mode 700).

```bash
ssh root@<host> mkdir -p soc-anonymizer
scp setup_ubuntu_gpu.sh soc_anonymize.py sample_files.py root@<host>:soc-anonymizer/
ssh root@<host> bash soc-anonymizer/setup_ubuntu_gpu.sh   # first run: driver, reboot, run again
```

It prints the full anonymizer command at the end (`--device cuda --review --review-workers 16`).
Use the same `ANON_KEY` as locally so tokens match. Override the model with
`MODEL=... bash setup_ubuntu_gpu.sh`. Raw exports and the map sit on the instance's disk, and GPU
instances are billed until **deleted** – copy back `out/` and delete the instance.

## Tests

Synthetic data only (`tests/fixtures.py`), no model download:

```bash
uv run --with pytest --with rich --with openpyxl --with python-calamine pytest -q tests
```
