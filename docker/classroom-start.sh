#!/usr/bin/env bash
# One local-only Docker container for classroom evaluation.
# The DB and generated password persist in two named Docker volumes.
set -Eeuo pipefail
export MONGODB_URI=mongodb://127.0.0.1:27017
export MONGODB_DB=cti_classroom
export LLM_BACKEND=ollama
export OLLAMA_HOST=127.0.0.1:11434
export OLLAMA_BASE_URL=http://127.0.0.1:11434
export EMBEDDING_MODEL=nomic-embed-text
export EMBEDDING_DIMENSIONS=768
export CHAT_RETRIEVAL=exact
export APP_USERNAME=ishan
export SIGNAL_DESK_LOCAL_QUEUE=1
export AUTO_MONITOR=0

mkdir -p /data/db /data/configdb
if [[ -z "${APP_PASSWORD:-}" ]]; then
  if [[ ! -s /data/configdb/cti-classroom-login ]]; then
    python3 -c 'import secrets; print(secrets.token_urlsafe(24))' > /data/configdb/cti-classroom-login
    chmod 600 /data/configdb/cti-classroom-login
  fi
  APP_PASSWORD="$(cat /data/configdb/cti-classroom-login)"
  export APP_PASSWORD
fi
if [[ "${#APP_PASSWORD}" -lt 16 ]]; then
  echo 'APP_PASSWORD must contain at least 16 characters' >&2
  exit 1
fi

children=()
stop_all() {
  trap - EXIT INT TERM
  echo 'Stopping local MongoDB / Ollama / CTI Sentinel...'
  for pid in "${children[@]}"; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
}
trap stop_all EXIT INT TERM

echo '[1/4] Starting local MongoDB (limited WiredTiger cache)...'
mongod --dbpath /data/db --bind_ip 127.0.0.1 --port 27017 \
       --wiredTigerCacheSizeGB 0.25 --quiet &
children+=("$!")
ready=0
for i in $(seq 1 90); do
  if python3 -c 'from pymongo import MongoClient; MongoClient("mongodb://127.0.0.1:27017", serverSelectionTimeoutMS=500).admin.command("ping")' >/dev/null 2>&1; then ready=1; break; fi
  if ! kill -0 "${children[0]}" 2>/dev/null; then echo 'MongoDB exited unexpectedly' >&2; exit 1; fi
  sleep 2
done
if [[ "$ready" -ne 1 ]]; then echo 'MongoDB was not ready' >&2; exit 1; fi

echo '[2/4] Loading included public-source intelligence snapshot (first run only)...'
python3 - <<'PY'
from backend import cloud, intelligence
cloud.bootstrap()
intelligence.seed_snapshot()
print('Public-source research dataset is ready.', flush=True)
PY

echo '[3/4] Starting the bundled Ollama model service...'
ollama serve &
children+=("$!")
ready=0
for i in $(seq 1 90); do
  if curl --silent --fail http://127.0.0.1:11434/api/tags >/dev/null; then ready=1; break; fi
  if ! kill -0 "${children[1]}" 2>/dev/null; then echo 'Ollama exited unexpectedly' >&2; exit 1; fi
  sleep 2
done
if [[ "$ready" -ne 1 ]]; then echo 'Ollama was not ready' >&2; exit 1; fi

# Ensure model downloads happened at BUILD time, not on the teacher's laptop.
python3 - <<'PY'
import json, os, urllib.request
with urllib.request.urlopen('http://127.0.0.1:11434/api/tags',timeout=10) as response:
    names=[m['name'] for m in json.load(response).get('models',[])]
for expected in (os.environ['OLLAMA_MODEL'], os.environ['EMBEDDING_MODEL']):
    if not any(name==expected or name.startswith(expected+':') for name in names):
        raise SystemExit('MISSING PREBAKED OLLAMA MODEL: '+expected+'; check Docker build logs')
print('Models packaged in image: '+', '.join(names), flush=True)
PY

printf '\n%s\n' '=========================================================='
echo ' CTI SENTINEL — LOCAL CLASSROOM MODE'
echo ' Website: http://localhost:8765/'
echo " Username: $APP_USERNAME"
echo " Password: $APP_PASSWORD"
echo " Offline AI: $OLLAMA_MODEL + $EMBEDDING_MODEL"
echo ' MongoDB: separate local persistent volume (not your Atlas)'
echo ' VirusTotal: local hashing works; online API needs runtime key'
echo '=========================================================='
echo ' Do not share this password or publish port 8765 publicly.'
printf '\n'

echo '[4/4] Starting the CTI Sentinel website...'
python3 -m flask --app app run --host 0.0.0.0 --port 8765 --no-reload &
children+=("$!")
wait -n "${children[@]}"
echo 'A required classroom service exited unexpectedly' >&2
exit 1
