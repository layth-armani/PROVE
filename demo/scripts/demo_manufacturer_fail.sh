#!/usr/bin/env bash
# Demo 4 — Manufacturer's own data fails the threshold.
# Supplier proof for 0xCD is valid, but the manufacturer's assembly efficiency
# for 0xCD is below 70% → Proof₂ generation fails.
set -euo pipefail
cd "$(dirname "$0")/../.."

echo "─────────────────────────────────────────────────"
echo "Demo 4 · Manufacturer threshold fails"
echo "  batch 0xCD (valid supplier proof, bad mfg data)"
echo "─────────────────────────────────────────────────"

cargo run --release -q -p verifier-cli -- verify \
    --batch-id 0xCD \
    --claim sustainable || true
