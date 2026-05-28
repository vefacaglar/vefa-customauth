#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

PIDS=()

cleanup() {
  if [ "${#PIDS[@]}" -eq 0 ]; then
    return
  fi

  echo
  echo "Stopping sample apps..."
  for pid in "${PIDS[@]}"; do
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
    fi
  done
}

free_port() {
  local port="$1"
  local pids
  # lsof returns non-zero when nothing is listening; guard so 'set -e' does not abort.
  pids="$(lsof -ti "tcp:${port}" -sTCP:LISTEN 2>/dev/null || true)"
  if [ -n "$pids" ]; then
    echo "Port ${port} is in use; stopping existing process(es): ${pids//$'\n'/ }"
    # shellcheck disable=SC2086
    kill $pids 2>/dev/null || true
    sleep 1
    pids="$(lsof -ti "tcp:${port}" -sTCP:LISTEN 2>/dev/null || true)"
    if [ -n "$pids" ]; then
      # shellcheck disable=SC2086
      kill -9 $pids 2>/dev/null || true
    fi
  fi
}

start_app() {
  local name="$1"
  local project="$2"
  local url="$3"
  local port="${url##*:}"

  free_port "$port"

  echo "Starting $name at $url"
  dotnet run --no-build --project "$ROOT_DIR/$project" --launch-profile http &
  PIDS+=("$!")
}

trap cleanup EXIT INT TERM

cd "$ROOT_DIR"

dotnet build --no-restore -p:UseSharedCompilation=false -nr:false -v:minimal

start_app "AuthServer" "samples/Vefa.CustomAuth.Sample.AuthServer/Vefa.CustomAuth.Sample.AuthServer.csproj" "http://localhost:5175"
start_app "API" "samples/Vefa.CustomAuth.Sample.Api/Vefa.CustomAuth.Sample.Api.csproj" "http://localhost:5098"
start_app "WebApp" "samples/Vefa.CustomAuth.Sample.WebApp/Vefa.CustomAuth.Sample.WebApp.csproj" "http://localhost:5043"

echo
echo "Sample apps are running:"
echo "  AuthServer: http://localhost:5175"
echo "  API:        http://localhost:5098"
echo "  WebApp:     http://localhost:5043"
echo
echo "Sign in with demo / demo. Press Ctrl+C to stop all apps."

wait
