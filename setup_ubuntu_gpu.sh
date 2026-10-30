#!/usr/bin/env bash
# Set up an Ubuntu 22.04/24.04 NVIDIA GPU host (e.g. a Linode GPU instance) to run soc_anonymize.py
# with the --review LLM on the host itself. Run as root ON the host.
#
# Serves an OpenAI-compatible API with vLLM on http://127.0.0.1:1234/v1 – the anonymizer's default
# --review-url, so no --allow-remote-review – bound to localhost only, behind ufw (SSH only).
# soc_anonymize.py must sit next to this script: its dependencies and the NER model are prefetched,
# and HF_HUB_OFFLINE=1 is added to root's ~/.bashrc so later runs stay offline. tmux is installed
# for long runs that survive an SSH disconnect.
#
# Usage:  ssh root@<host> mkdir -p soc-anonymizer
#         scp setup_ubuntu_gpu.sh soc_anonymize.py sample_files.py root@<host>:soc-anonymizer/
#         ssh root@<host> bash soc-anonymizer/setup_ubuntu_gpu.sh
#         Re-run after the reboot it asks for (driver install). Safe to re-run any time.
#
# Settings (env vars):
#   MODEL         Hugging Face id               (default: Qwen/Qwen3-8B-AWQ, fits a 20 GB GPU)
#   SERVED_NAME   id reported by /v1/models     (default: last part of MODEL, lower-case)
#   MAX_LEN       context length                (default: 16384)
#   GPU_UTIL      share of GPU memory for vLLM  (default: 0.75, the rest is for the NER model)
#   TP            tensor-parallel size          (default: number of GPUs)
#   VLLM_VERSION  pin vLLM, e.g. 0.11.0          (default: latest)
#   HF_TOKEN      only needed for gated models
#
# Remember: cloud GPU instances (Linode included) bill while they exist, even powered off. Delete
# the instance when done.
set -euo pipefail

MODEL="${MODEL:-Qwen/Qwen3-8B-AWQ}"
SERVED_NAME="${SERVED_NAME:-$(basename "$MODEL" | tr '[:upper:]' '[:lower:]')}"
MAX_LEN="${MAX_LEN:-16384}"
GPU_UTIL="${GPU_UTIL:-0.75}"
VLLM_VERSION="${VLLM_VERSION:-}"
PORT=1234                      # LM Studio's port = soc_anonymize.py default --review-url
API_KEY="lm-studio"            # soc_anonymize.py always sends "Bearer lm-studio"
APP_DIR=/opt/llm
SVC_USER=llm
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR=/root/soc             # raw exports, outputs and .private/ (map, review report)

say() { printf '\n\033[1;32m== %s\033[0m\n' "$*"; }
die() { printf '\033[1;31m%s\033[0m\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run as root"
command -v apt-get >/dev/null || die "this script expects Ubuntu/Debian"
[[ -f "$HERE/soc_anonymize.py" ]] || die "copy soc_anonymize.py next to this script ($HERE) first"
export DEBIAN_FRONTEND=noninteractive

say "base packages"
apt-get update -q
apt-get install -yq curl ca-certificates ufw tmux ubuntu-drivers-common build-essential python3-dev

say "firewall: SSH only"
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
ufw allow OpenSSH >/dev/null
ufw --force enable >/dev/null
ufw status | sed -n '1,6p'

say "NVIDIA driver"
if ! nvidia-smi >/dev/null 2>&1; then
    lspci | grep -qi nvidia || die "no NVIDIA GPU found – is this a GPU instance?"
    ubuntu-drivers install --gpgpu || ubuntu-drivers install
    # the -server (gpgpu) driver needs the matching utils for nvidia-smi; --gpgpu installs
    # nvidia-headless-no-dkms-<ver>-server-open, not nvidia-driver-<ver>
    drv=$(dpkg -l 'nvidia-driver-*' 'nvidia-headless-no-dkms-*' 2>/dev/null | awk '/^ii/{print $2}' | grep -o '[0-9]\+' | head -1 || true)
    [[ -n "$drv" ]] && apt-get install -yq "nvidia-utils-${drv}-server" 2>/dev/null || true
    say "driver installed – reboot, then run this script again:  reboot"
    exit 0
fi
nvidia-smi --query-gpu=name,memory.total,driver_version --format=csv,noheader
TP="${TP:-$(nvidia-smi -L | wc -l)}"

say "service user and uv"
id "$SVC_USER" >/dev/null 2>&1 || useradd --system --create-home --home-dir "$APP_DIR" --shell /usr/sbin/nologin "$SVC_USER"
if ! command -v uv >/dev/null; then
    curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR=/usr/local/bin INSTALLER_NO_MODIFY_PATH=1 sh
fi

say "vLLM ${VLLM_VERSION:-latest}"
sudo -u "$SVC_USER" -H bash -c "
    set -e; cd '$APP_DIR'
    [[ -x venv/bin/python ]] || uv venv --python 3.12 venv
    VIRTUAL_ENV='$APP_DIR/venv' uv pip install --torch-backend=auto 'vllm${VLLM_VERSION:+==$VLLM_VERSION}'
"
VLLM="$APP_DIR/venv/bin/vllm"

say "download $MODEL"
sudo -u "$SVC_USER" -H env HF_TOKEN="${HF_TOKEN:-}" "$APP_DIR/venv/bin/hf" download "$MODEL" >/dev/null \
  || sudo -u "$SVC_USER" -H env HF_TOKEN="${HF_TOKEN:-}" "$APP_DIR/venv/bin/huggingface-cli" download "$MODEL" >/dev/null

# Flags that differ between vLLM versions: only pass what this build knows.
HELP=$("$VLLM" serve --help=all 2>/dev/null || "$VLLM" serve --help 2>/dev/null || true)
EXTRA=""                       # goes into ExecStart verbatim (systemd quoting)
# never write prompts (= your SOC text) to the journal
grep -q -- '--disable-log-requests' <<<"$HELP" && ! grep -q -- '--enable-log-requests' <<<"$HELP" \
    && EXTRA+=" --disable-log-requests"
# Qwen3 thinks before answering; the reviewer wants the JSON straight away (max_tokens 2048)
if [[ "${MODEL,,}" == *qwen3* ]] && grep -q -- '--default-chat-template-kwargs' <<<"$HELP"; then
    EXTRA+=" --default-chat-template-kwargs '{\"enable_thinking\":false}'"
fi

say "systemd service vllm.service"
cat >/etc/systemd/system/vllm.service <<EOF
[Unit]
Description=vLLM OpenAI-compatible server ($MODEL), localhost only
After=network-online.target
Wants=network-online.target

[Service]
User=$SVC_USER
WorkingDirectory=$APP_DIR
Environment=HF_HUB_OFFLINE=1
Environment=VLLM_NO_USAGE_STATS=1
Environment=DO_NOT_TRACK=1
# FlashInfer's sampler is JIT-compiled with nvcc, and the driver alone ships no CUDA toolkit
Environment=VLLM_USE_FLASHINFER_SAMPLER=0
ExecStart=$VLLM serve $MODEL --host 127.0.0.1 --port $PORT --api-key $API_KEY \\
    --served-model-name $SERVED_NAME --max-model-len $MAX_LEN \\
    --gpu-memory-utilization $GPU_UTIL --tensor-parallel-size $TP$EXTRA
Restart=on-failure
RestartSec=10
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable vllm >/dev/null
systemctl restart vllm

say "waiting for the server (first start compiles kernels, a few minutes)"
for _ in $(seq 1 120); do
    if curl -sf -H "Authorization: Bearer $API_KEY" "http://127.0.0.1:$PORT/v1/models" >/dev/null; then
        break
    fi
    systemctl is-active --quiet vllm || { journalctl -u vllm -n 40 --no-pager; die "vllm.service failed"; }
    sleep 5
done
curl -sf -H "Authorization: Bearer $API_KEY" "http://127.0.0.1:$PORT/v1/models" >/dev/null \
    || { journalctl -u vllm -n 40 --no-pager; die "server not up after 10 minutes"; }

say "smoke test (structured JSON output, synthetic text)"
curl -sf "http://127.0.0.1:$PORT/v1/chat/completions" \
    -H "Content-Type: application/json" -H "Authorization: Bearer $API_KEY" \
    -d '{"model":"'"$SERVED_NAME"'","temperature":0,"max_tokens":200,
         "messages":[{"role":"user","content":"List person names in: Priya Sharma reset the VPN token for USER_1a2b3c4d."}],
         "response_format":{"type":"json_schema","json_schema":{"name":"leaks","strict":true,
           "schema":{"type":"object","properties":{"leaks":{"type":"array","items":{"type":"string"}}},
                     "required":["leaks"],"additionalProperties":false}}}}' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["choices"][0]["message"]["content"])'

say "anonymizer dependencies + NER model (model weights only, no data sent)"
# --prefetch refuses to run offline; a re-run from a shell that sourced ~/.bashrc has HF_HUB_OFFLINE=1
(cd "$HERE" && env -u HF_HUB_OFFLINE uv run soc_anonymize.py --prefetch)

say "HF_HUB_OFFLINE=1 in ~/.bashrc (real runs never reach Hugging Face)"
grep -qxF 'export HF_HUB_OFFLINE=1' ~/.bashrc 2>/dev/null || echo 'export HF_HUB_OFFLINE=1' >>~/.bashrc

install -d -m 700 "$DATA_DIR" "$DATA_DIR/in" "$DATA_DIR/out" "$DATA_DIR/.private"

say "ready: $SERVED_NAME on 127.0.0.1:$PORT (not reachable from outside)"
cat <<EOF
Copy exports into $DATA_DIR/in (mode 700). Use the same ANON_KEY as earlier runs for matching tokens.
Log in again (or: source ~/.bashrc) for HF_HUB_OFFLINE=1; run inside tmux so a dropped SSH
session doesn't kill the run (tmux new -s soc, detach Ctrl-b d, back with tmux attach -t soc).

  tmux new -s soc
  cd $HERE
  export ANON_KEY=...
  uv run soc_anonymize.py $DATA_DIR/in -o $DATA_DIR/out --device cuda --domains ... \\
      --map $DATA_DIR/.private/mapping.json \\
      --review --review-apply --review-workers 16 --review-report $DATA_DIR/.private/review.jsonl

Logs:    journalctl -u vllm -f
Stop:    systemctl stop vllm      (billing continues until the instance is deleted)
When done, copy back only $DATA_DIR/out, then delete the instance (raw data and map are on its disk).
EOF
