#!/usr/bin/env bash
# Copy a demonstration profile into the working tree.
# Usage: ./scripts/reset-demo.sh <vulnerable|fixed|agent-secret-only|agent-image-only>
set -euo pipefail

STATES="vulnerable fixed agent-secret-only agent-image-only"
STATE="${1:-}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ -z "$STATE" || ! " $STATES " =~ " $STATE " ]]; then
  echo "Usage: $0 <${STATES// /|}>" >&2
  exit 1
fi

cp "$ROOT/demo-states/$STATE/app.py" "$ROOT/app.py"
cp "$ROOT/demo-states/$STATE/Dockerfile" "$ROOT/Dockerfile"

echo "Working tree reset to the '$STATE' profile (app.py, Dockerfile)."
echo "Next: git add app.py Dockerfile && git commit -m \"demo: $STATE state\" && git push"
