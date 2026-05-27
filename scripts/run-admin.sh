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

trap cleanup EXIT INT TERM

cd "$ROOT_DIR"

echo "Building solution..."
dotnet build --no-restore -p:UseSharedCompilation=false -nr:false -v:minimal

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
