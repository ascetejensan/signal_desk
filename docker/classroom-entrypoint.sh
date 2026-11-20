#!/usr/bin/env bash
# Optimized all-in-one classroom service; no Atlas/API secrets in image.
set -Eeuo pipefail
export MONGODB_URI='mongodb://127.0.0.1:27017'
export MONGODB_DB='cti_sentinel_classroom'
export LLM_BACKEND='ollama'
export OLLAMA_BASE_URL='http://127.0.0.1:11434'
export OLLAMA_HOST='127.0.0.1:11434'
export OLLAMA_MODEL="${OLLAMA_MODEL:-llama3.2:1b}"
export EMBEDDING_MODEL='nomic-embed-text'
export EMBEDDING_DIMENSIONS=768
export CHAT_RETRIEVAL=exact
export OLLAMA_CONTEXT_LENGTH=2048
export OLLAMA_NUM_PARALLEL=1
export OLLAMA_MAX_LOADED_MODELS=1
export OLLAMA_KEEP_ALIVE=0
export APP_USERNAME="${APP_USERNAME:-ishan}"
export SIGNAL_DESK_LOCAL_QUEUE=1
export AUTO_MONITOR=0

mkdir -p /data/db /data/configdb
if [[ -z "${APP_PASSWORD:-}" ]]; then
  if [[ ! -s /data/configdb/cti-classroom-password ]]; then
    python -c 'import secrets; print(secrets.token_urlsafe(24))' > /data/configdb/cti-classroom-password
    chmod 600 /data/configdb/cti-classroom-password
  fi
  APP_PASSWORD="$(cat /data/configdb/cti-classroom-password)"
  export APP_PASSWORD
fi
if [[ "${#APP_PASSWORD}" -lt 16 ]]; then
  echo 'APP_PASSWORD must have at least 16 characters' >&2
  exit 1
fi

pids=()
stop() {
  trap - INT TERM EXIT
  for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
}
trap stop INT TERM EXIT

# 256 MiB MongoDB WiredTiger cache; localhost-only DB access.
mongod --dbpath /data/db --bind_ip 127.0.0.1 --port 27017 --wiredTigerCacheSizeGB 0.25 --quiet &
pids+=("$!")
echo 'Starting local MongoDB...'
ready=0
for i in $(seq 1 90); do
  if python -c 'from pymongo import MongoClient; MongoClient("mongodb://127.0.0.1:27017",serverSelectionTimeoutMS=500).admin.command("ping")' >/dev/null 2>&1; then ready=1; break; fi
  if ! kill -0 "${pids[0]}" 2>/dev/null; then echo 'MongoDB stopped unexpectedly' >&2; exit 1; fi
  sleep 2
done
if [[ "$ready" != 1 ]]; then echo 'MongoDB failed to start' >&2; exit 1; fi

# Import bundled public metadata and intelligence; no private Atlas dump.
echo 'Initializing bundled public research snapshot...'
python - <<'PY'
from backend import cloud, intelligence
cloud.bootstrap()
intelligence.seed_snapshot()
print('Public classroom data initialized.',flush=True)
PY

echo "Starting preloaded Ollama ($OLLAMA_MODEL)..."
ollama serve &
pids+=("$!")
ready=0
for i in $(seq 1 90); do
  if curl -fsS http://127.0.0.1:11434/api/tags >/dev/null; then ready=1; break; fi
  if ! kill -0 "${pids[1]}" 2>/dev/null; then echo 'Ollama exited unexpectedly' >&2; exit 1; fi
  sleep 2
done
if [[ "$ready" != 1 ]]; then echo 'Ollama failed to start' >&2; exit 1; fi

printf '\n================ CTI SENTINEL (CLASSROOM) ================\n'
printf 'Website:  http://localhost:8765/\n'
printf 'Username: %s\n' "$APP_USERNAME"
printf 'Password: %s\n' "$APP_PASSWORD"
printf 'AI model: %s (preloaded; no separate download)\n' "$OLLAMA_MODEL"
printf 'Embedding: nomic-embed-text (preloaded)\n'
printf 'Database: separate persistent MongoDB, local to this container\n'
printf 'VirusTotal: local hashing works; online scan requires runtime API key\n'
printf '===========================================================\n\n'

python -m flask --app app run --host 0.0.0.0 --port 8765 --no-reload &
pids+=("$!")
wait -n "${pids[@]}"
echo 'A required classroom service stopped.' >&2
exit 1
