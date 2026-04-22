#!/usr/bin/env bash
# Demo 2 — Supplier data fails sustainability thresholds.
# Supplier never issued a Proof₁ for 0x99 → manufacturer has nothing to prove
# against → 404 CANNOT PROVE.
set -euo pipefail
cd "$(dirname "$0")/../.."

echo "─────────────────────────────────────────────────"
echo "Demo 2 · Supplier claim fails"
echo "  batch 0x99 (dirty — supplier cannot prove)"
echo "─────────────────────────────────────────────────"

cargo run --release -q -p verifier-cli -- verify \
    --batch-id 0x99 \
    --claim sustainable || true
