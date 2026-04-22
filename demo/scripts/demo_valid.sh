#!/usr/bin/env bash
# Demo 1 — Valid path. Clean supplier batch + clean manufacturer data → VALID.
set -euo pipefail
cd "$(dirname "$0")/../.."

echo "─────────────────────────────────────────────────"
echo "Demo 1 · Valid path"
echo "  batch 0x42 (clean supplier, clean manufacturer)"
echo "─────────────────────────────────────────────────"

cargo run --release -q -p verifier-cli -- verify \
    --batch-id 0x42 \
    --claim sustainable
