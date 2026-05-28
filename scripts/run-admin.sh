#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

PIDS=()

cleanup() {
  if [ "${#PIDS[@]}" -eq 0 ]; then
    return
  fi

  echo
  echo "Stopping Admin sample app..."
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

trap cleanup EXIT INT TERM

cd "$ROOT_DIR"

echo "Building solution..."
dotnet build --no-restore -p:UseSharedCompilation=false -nr:false -v:minimal

free_port 5220

echo "Starting Vefa.CustomAuth.Sample.Admin at http://localhost:5220"
dotnet run --no-build --project "$ROOT_DIR/samples/Vefa.CustomAuth.Sample.Admin/Vefa.CustomAuth.Sample.Admin.csproj" &
PIDS+=("$!")

echo
echo "Admin Portal is running:"
echo "  Dashboard:  http://localhost:5220/customauth"
echo "  OIDC metadata: http://localhost:5220/.well-known/openid-configuration"
echo
echo "Press Ctrl+C to stop the application."

wait
