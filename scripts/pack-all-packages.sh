#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  echo "Usage: scripts/pack-all-packages.sh <version> [output-directory]"
  echo "Example: scripts/pack-all-packages.sh 1.0.0 ./artifacts"
  exit 1
fi

VERSION="$1"
OUTPUT_DIR="${2:-$ROOT_DIR/artifacts/packages}"

PROJECTS=(
  "src/Vefa.CustomAuth.Core/Vefa.CustomAuth.Core.csproj"
  "src/Vefa.CustomAuth.Tokens/Vefa.CustomAuth.Tokens.csproj"
  "src/Vefa.CustomAuth.AspNetCore/Vefa.CustomAuth.AspNetCore.csproj"
  "src/Vefa.CustomAuth.EntityFrameworkCore/Vefa.CustomAuth.EntityFrameworkCore.csproj"
  "src/Vefa.CustomAuth.MongoDB/Vefa.CustomAuth.MongoDB.csproj"
  "src/Vefa.CustomAuth.AdminUI/Vefa.CustomAuth.AdminUI.csproj"
  "src/Vefa.CustomAuth.Server/Vefa.CustomAuth.Server.csproj"
)

mkdir -p "$OUTPUT_DIR"

cd "$ROOT_DIR"

echo "Packing Vefa.CustomAuth packages"
echo "Version: $VERSION"
echo "Output:  $OUTPUT_DIR"
echo

for project in "${PROJECTS[@]}"; do
  echo "Packing $project"
  dotnet pack "$project" \
    --configuration Release \
    --output "$OUTPUT_DIR" \
    -p:Version="$VERSION"
done

echo
echo "Packages written to $OUTPUT_DIR"
