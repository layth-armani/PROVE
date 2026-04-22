#!/usr/bin/env bash
# Demo 3 — Proof-swap attack. The manufacturer attempts to answer a request for
# 0x42 using a Proof₁ from a different batch (0xAB). The outer circuit's
# batch_id binding makes Proof₂ generation unsatisfiable.
set -euo pipefail
cd "$(dirname "$0")/../.."

echo "─────────────────────────────────────────────────"
echo "Demo 3 · Proof-swap attack"
echo "  batch 0x42 — manufacturer cheats with another batch's Proof₁"
echo "─────────────────────────────────────────────────"

cargo run --release -q -p verifier-cli -- verify \
    --batch-id 0x42 \
    --claim sustainable \
    --force-swap || true
