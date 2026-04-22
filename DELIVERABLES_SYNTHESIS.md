# PROVE — Technical Deliverables

**HackSummit Builder Challenge 2026 · Work Package 3 · Powered by SICPA**
*Privacy-Preserving Battery Passport via Chained Zero-Knowledge Proofs*

---

## 1. Environmental and Regulatory Problem

The **EU Battery Regulation** (2023/1542, enforced from 2027) requires every industrial battery to carry a verifiable digital passport covering material sourcing and manufacturing sustainability — spanning at least three parties: lithium supplier, cell manufacturer, and EU regulator.

Each party holds commercially sensitive data they cannot disclose. Today's compliance relies on self-reporting and periodic audits, creating three compounding failure modes: **opacity** (no cross-party verification), **fraud surface** (certifications can be forged), and **lag** (non-compliance discovered months later).

---

## 2. System Architecture

PROVE is a four-component Rust workspace simulating the full verification lifecycle:

| Component | Role |
|---|---|
| `zkp-core` | Shared cryptographic library (circuits, proving, serialization) |
| `supplier-service` | HTTP server simulating a lithium supplier (port 3001) |
| `manufacturer-service` | HTTP server simulating a cell manufacturer (port 3002) |
| `verifier-cli` | CLI tool representing the EU regulator |

---

## 3. Proof Chain: How Upstream and Downstream Proofs Are Linked

The chain is anchored by a `batch_id` identifying a physical lithium shipment (intended to be derived from a SICPA tamper-resistant tag in production).

1. **Supplier generates Proof₁** — proves private sensor data satisfies sustainability thresholds without revealing it. `batch_id` is cryptographically bound to the proof.
2. **Supplier ships `(batch_id, Proof₁)` to manufacturer** — the physical/digital handoff.
3. **EU triggers verification** — scans the battery tag, sends `(batch_id, claim, nonce)` to the manufacturer.
4. **Manufacturer generates Proof₂** — verifies Proof₁ is valid and bound to the correct batch, then proves its own efficiency threshold is met. Any mismatch aborts with an error.

The binding property ensures a manufacturer cannot substitute another supplier's proof. The nonce prevents pre-computed responses.

---

## 4. Zero-Knowledge Proof Systems Used

- **Proof₁ — Groth16 over BLS12-377**: constant-size (~192 bytes), single pairing-check verification, 128-bit security. Requires a per-circuit trusted setup.
- **Proof₂ — Groth16 over BW6-761**: the outer curve whose base field equals BLS12-377's scalar field, enabling in-circuit recursive verification without expensive non-native arithmetic. Circuit is fully defined; full proving synthesis is pending (see §6).

---

## 5. Technical Choices — Justification

| Choice | Rationale |
|---|---|
| **Rust** | Only language with a production-grade Groth16 + recursion stack (Arkworks). |
| **Groth16** | Smallest proofs (~192 bytes), fastest verification (single pairing check) — ideal for a one-scan-per-battery use case. |
| **BLS12-377 / BW6-761** | Only standardized pairing-friendly 2-chain enabling recursive Groth16 without non-native arithmetic. |
| **Arkworks 0.5.0** | Only pure-Rust, production-grade ZKP framework with stable BW6-761 support. |
| **Axum + Tokio** | Idiomatic async Rust web stack with no legacy dependencies. |

---

## 6. Tool Maturity and Limitations

Arkworks is production-grade for the inner circuit (Proof₁): trusted setup, proving, and verification work reliably.

For recursive proving (Proof₂ over BW6-761), the library is significantly less mature. The outer circuit has tens of millions of constraints, requiring tens of gigabytes of RAM and minutes of compute — impractical on hackathon hardware. The circuit is fully written and compiles correctly, but is not yet wired to the final proving step; the manufacturer currently performs the same checks natively and returns a mock proof.

---

## 7. Challenges and Open Problems

- **Physical-to-digital binding**: the ZKP chain is only as strong as the link between a physical batch and its `batch_id` — requires external physical authentication (e.g., SICPA tags).
- **Mass-balance fraud**: one Proof₁ could theoretically certify more batteries than the batch's lithium could produce — requires per-battery commitments or a shared ledger.
- **Trusted setup**: Groth16 requires a multi-party ceremony in production; a compromised setup allows arbitrary forgery.
- **Circuit update agility**: changing a regulatory threshold requires a new circuit and a new trusted setup ceremony.
- **Prover hardware**: outer BW6-761 proving requires GPU acceleration or outsourced proving in production.
- **Multi-tier chains**: the 2-chain supports one level of recursion; deeper supply chains need a different accumulation scheme.
- **Revocation**: no mechanism to invalidate a proof once issued.

---

## 8. Extensibility to Different Supply Chains

The architecture is claim- and sector-agnostic:

- **New claim type** (e.g., `ConflictFree`): add a variant and define its thresholds — no circuit changes needed.
- **New sector** (e.g., solar panels): replace the private input fields and threshold constants — the proof chain, API, and CLI are unchanged.
- **Additional supply chain tier**: implement a new recursive circuit per tier. The primary extensibility cost is one trusted setup ceremony per circuit; a universal SNARK (PLONK, Halo2) would reduce this to a single shared setup.

---

## 9. Proof of Concept — Demo

Five end-to-end scenarios runnable out of the box:

| Script | Expected result |
|---|---|
| `demo_valid.sh` | ✔ VALID — happy path |
| `demo_invalid_claim.sh` | ✗ Supplier data fails threshold → no Proof₁ issued |
| `demo_proof_swap.sh` | ✗ Manufacturer swaps batch → `batch_id` mismatch |
| `demo_manufacturer_fail.sh` | ✗ Manufacturer efficiency below threshold |
| `demo_forge.sh` | ✗ Tampered proof hex rejected at deserialization |

```bash
cargo build --release
cargo run --release -p supplier-service     # terminal 1
cargo run --release -p manufacturer-service # terminal 2
./demo/scripts/demo_valid.sh                # terminal 3
```

---

*Built in 18 hours at HackSummit Builder Challenge — April 22–23, 2026 · Lausanne.*
*Work Package 3: "Prove It's Green Without Sharing Secrets" — co-designed with SICPA.*
