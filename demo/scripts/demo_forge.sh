#!/usr/bin/env bash
# Demo 5 — Forgery on the wire. Manufacturer generates a valid Proof₂, then
# tampers with a byte before shipping → EU verifier rejects it.
set -euo pipefail
cd "$(dirname "$0")/../.."

echo "─────────────────────────────────────────────────"
echo "Demo 5 · Forgery on the wire"
echo "  batch 0x42 — valid Proof₂ mutated in transit"
echo "─────────────────────────────────────────────────"

cargo run --release -q -p verifier-cli -- verify \
    --batch-id 0x42 \
    --claim sustainable \
    --force-forge || true
