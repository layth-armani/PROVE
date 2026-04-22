# PROVE — Technical Deliverables

**HackSummit Builder Challenge 2026 · Work Package 3 · Powered by SICPA**
*Privacy-Preserving Battery Passport via Chained Zero-Knowledge Proofs*

---

## 1. Environmental and Regulatory Problem

The **EU Battery Regulation** (Regulation 2023/1542, in force from 2027) requires every industrial battery to carry a digital battery passport: a verifiable record of where its materials were sourced, how sustainably they were extracted, and how efficiently the battery was manufactured. For lithium-ion batteries, this spans at minimum three parties — a lithium miner/supplier, a cell manufacturer, and an EU regulatory body.

The problem is structural: **each party holds commercially sensitive data they cannot disclose**.

- The lithium supplier's water consumption, recycled-content ratio, and sourcing region determine their competitive position and are trade secrets.
- The cell manufacturer's assembly efficiency and energy spend per cell are proprietary production metrics.
- Neither party can share their raw figures with regulators, auditors, or competitors — yet regulators need end-to-end assurance.

Today's compliance relies on paper attestations, self-reporting, and occasional third-party audits. This creates three compounding failure modes:

1. **Opacity**: no party can verify another's claims without disclosing their own data.
2. **Fraud surface**: certifications can be forged, recycled across batches, or applied to unlabeled product.
3. **Lag**: audits are periodic; non-compliance is discovered months after the fact.

The regulatory goal — prove the supply chain is clean — is fundamentally at odds with the economic reality that the supply chain is made of competitors.

---

## 2. System Architecture

PROVE is a four-component Rust workspace that simulates the full verification lifecycle across supplier, manufacturer, and EU regulator.

```
PROVE/
├── crates/
│   ├── zkp-core/              # shared cryptographic library
│   ├── supplier-service/      # Axum HTTP server, port 3001
│   ├── manufacturer-service/  # Axum HTTP server, port 3002
│   └── verifier-cli/          # EU regulator CLI tool
├── demo/scripts/              # five end-to-end scenario scripts
└── data/keys/                 # persisted proving/verifying keys
```

### zkp-core

The cryptographic foundation. Contains:
- `types.rs` — canonical type aliases (`InnerCurve = Bls12_377`, `OuterCurve = BW6_761`, `BatchId`, `Claim`, `SupplierSecret`, `ManufacturerSecret`)
- `supplier_circuit.rs` — `SupplierCircuit`, a fully functional Groth16 R1CS circuit over BLS12-377
- `manufacturer_circuit.rs` — `ManufacturerCircuit`, a complete recursive R1CS circuit over BW6-761 (circuit defined; Groth16 synthesis pending)
- `prove.rs` — `prove_supplier` / `verify_supplier` (real Groth16), `prove_manufacturer` / `verify_manufacturer` (native validation + mock proof)
- `setup.rs` — `load_or_generate`: runs or reloads the inner Groth16 trusted setup
- `serialization.rs` — canonical hex (de)serialization for proofs and verifying keys

### supplier-service (port 3001)

An Axum HTTP server simulating a lithium supplier. On startup it runs the inner Groth16 trusted setup (or loads from `data/keys/`), pre-seeds four lithium batches with private sensor data, generates real Groth16 Proof₁ for each batch that passes thresholds, and ships valid proofs to the manufacturer via `POST /ingest`.

HTTP surface: `GET /health`, `GET /vk` (inner verifying key as hex), `POST /proof1`.

### manufacturer-service (port 3002)

An Axum HTTP server simulating a battery cell manufacturer. Stores received supplier proofs keyed by `batch_id`. On a verify request, performs native constraint validation (inner proof integrity, batch_id binding, claim_code binding, efficiency threshold), then returns a serialized mock Proof₂. In the full build, this step would call `Groth16::prove` over BW6-761 instead.

HTTP surface: `GET /health`, `GET /vk_outer`, `POST /ingest`, `POST /verify`.

### verifier-cli

A CLI tool representing the EU regulator. Accepts `--batch-id` and `--claim`, generates a fresh random nonce, fetches the outer verifying key from the manufacturer, POSTs a verify request, receives Proof₂, and attempts to deserialize it via `proof_from_hex::<BW6_761>()`. A successful deserialization reports `✔ VALID`; a hex error (e.g. from wire tampering) reports `✗ INVALID`.

---

## 3. Proof Chain: How Upstream and Downstream Proofs Are Linked

The chain is anchored by a `batch_id` — a u64 that identifies a specific physical lithium shipment, intended in production to be derived from a SICPA tamper-resistant tag on the material package.

**Step 1 — Supplier generates Proof₁**

The supplier runs `prove_supplier(pk, batch_id, claim, secret)`. The `SupplierCircuit` encodes `batch_id` and `claim_code` as public inputs and `water_liters_per_kg` / `recycled_content_pct` as private witnesses. The circuit enforces:
- `water ≤ 2000` (R1CS range check via bit decomposition)
- `recycled ≥ 10` (R1CS range check)
- `claim_code == 1` (equality constraint)
- `batch_id` fits in 64 bits (range check)

The resulting Groth16 proof commits to `batch_id` cryptographically — it is part of the proof's public input binding and cannot be detached.

**Step 2 — Supplier ships (batch_id, Proof₁) to manufacturer**

The manufacturer stores it keyed by `batch_id`. This is the physical/digital handoff.

**Step 3 — EU triggers verification**

The EU scans the battery's tag, reads `batch_id`, and sends `{ batch_id, claim, nonce }` to the manufacturer.

**Step 4 — Manufacturer generates Proof₂**

`prove_manufacturer` (native build) / `ManufacturerCircuit::generate_constraints` (full build):
1. Calls `verify_supplier(inner_vk, inner_proof, inner_public_inputs)` — the inner Groth16 proof is checked
2. Compares `inner_public_inputs[0] == InnerFr::from(batch_id.0)` — the supplier's proof must have been issued for exactly this batch, not any other
3. Checks `claim_code` matches
4. Checks `assembly_efficiency_pct ≥ 70`

Any failure aborts proof generation with a 422 error. Success produces Proof₂ bound to `(batch_id, claim_code, nonce)`.

**The binding property**: the same 64 bits that form `batch_id` in the outer public input are bit-shared into the inner circuit's `BooleanInputVar`. The `Groth16VerifierGadget` verifies the inner proof against those exact bits in-circuit. A manufacturer who substitutes a different supplier's proof will have mismatched bits, making the outer R1CS unsatisfiable.

**The nonce**: a fresh 64-bit random value per request. It is included as a public input in the outer circuit and bound via a trivial multiply constraint. This prevents a manufacturer from pre-computing and caching Proof₂ responses.

---

## 4. Zero-Knowledge Proof Systems Used

### Inner proof (Proof₁) — Groth16 over BLS12-377

**Groth16** is a pairing-based zk-SNARK. A prover with a valid witness produces a proof of three elliptic curve group elements (A ∈ G1, B ∈ G2, C ∈ G1). Verification is a constant-time pairing check regardless of circuit size. Properties:
- Proof size: ~192 bytes (compressed BLS12-377 group elements)
- Verification time: single pairing check (~milliseconds)
- Requires a trusted setup per circuit (toxic waste must be discarded)
- Soundness: computationally sound under the discrete logarithm assumption in bilinear groups (128-bit security on BLS12-377)

**BLS12-377** is a pairing-friendly elliptic curve with 128-bit security and a specific arithmetic structure (its scalar field has a large power-of-two subgroup) that makes it ideal as the inner curve in a 2-chain for recursive proving.

### Outer proof (Proof₂) — Groth16 over BW6-761 (defined; synthesis pending)

**BW6-761** is the paired companion to BLS12-377. Its base field is equal to BLS12-377's scalar field, which is the defining property that makes recursive verification tractable: the `Groth16VerifierGadget` can embed BLS12-377 pairing arithmetic as native field operations over BW6-761, rather than requiring expensive non-native field arithmetic.

The `ManufacturerCircuit` uses `ark_groth16::constraints::Groth16VerifierGadget<BLS12_377, BLS12_377PairingVar>` to verify Proof₁ inside the R1CS constraint system. In the hackathon build, this verification is performed natively in Rust (not via circuit synthesis); the circuit struct with all constraints is written and compiles, but is not yet connected to `Groth16::prove` over BW6-761.

---

## 5. Technical Choices — Justification

| Choice | Rationale |
|---|---|
| **Rust** | Memory safety, zero-cost abstractions, and the entire Arkworks ecosystem is Rust-native. No alternative language has a production-grade Groth16 + recursion stack. |
| **Arkworks 0.5.0** | The only pure-Rust, production-grade ZKP framework with a stable API. Used in Aleo, Espresso Systems, and Penumbra. Alternative: Bellman (Zcash) is unmaintained for new curves; gnark (Go) has no BW6-761 gadgets. |
| **Groth16** | Smallest possible proofs (~192 bytes), fastest verification (single pairing check). For a regulatory scanner use case — one scan per battery label — these properties dominate. Alternatives: PLONK/STARKs would eliminate the trusted setup but produce larger proofs (1–10 KB) and are slower to verify. |
| **BLS12-377 / BW6-761 2-chain** | This is the only publicly standardized pairing-friendly 2-chain where the inner scalar field equals the outer base field, making recursive Groth16 feasible without expensive non-native arithmetic. Used by the Zexe paper (the theoretical basis for this architecture) and implemented in Arkworks. |
| **Axum + Tokio** | Modern async Rust web stack; matches the rest of the codebase idiomatically. No legacy dependencies, excellent performance. |
| **batch_id as u64 (public input)** | Small, fixed-size, maps cleanly to a physical tag identifier, and fits within the BLS12-377 scalar field without encoding gymnastics. |

---

## 6. Tool Maturity and Limitations

**Arkworks 0.5.0** is production-grade for the inner circuit (Groth16 over BLS12-377). Trusted setup, proving, and verification all work reliably. The serialization API is stable.

For recursive proving (Groth16 over BW6-761 via `Groth16VerifierGadget`), Arkworks is significantly less mature:
- The `Groth16VerifierGadget` for BLS12-377/BW6-761 compiles and generates constraints correctly, but real `Groth16::prove` calls over BW6-761 are extremely slow — the outer circuit has tens of millions of constraints due to the in-circuit pairing computation.
- Memory usage during BW6-761 setup and proving is in the tens of gigabytes; this is impractical for hackathon hardware.
- The `BooleanInputVar` and field emulation APIs have limited documentation; getting bit-sharing right for cross-field binding required significant trial-and-error.
- `ark-crypto-primitives` 0.5.0's `SNARKGadget` trait signature changed between minor versions, causing compilation failures that required pinning specific versions of the full dependency graph.

The Groth16 trusted setup for the inner circuit takes 5–10 seconds on first boot; this is acceptable for a demo but would need a pre-computed ceremony for production.

---

## 7. Challenges and Open Problems in Applying ZKPs to Real Battery Supply Chains

**Physical-to-digital binding.** The entire cryptographic chain is only as strong as the link between a physical lithium batch and its `batch_id`. Nothing in the ZKP protocol prevents a manufacturer from scanning a legitimate tag onto a different batch. This is where physical authentication (e.g., SICPA tamper-evident labels, spectroscopic fingerprinting) must be integrated. The ZKP system assumes this binding is solved externally.

**Mass-balance fraud.** A single supplier proof could theoretically be used to certify more batteries than the batch's lithium could physically produce. The current system has no constraint bounding the number of Proof₂ instances derivable from one Proof₁. This requires either per-battery unique commitments (expensive) or batch-scoped counters published to a shared ledger.

**Trusted setup ceremony.** Groth16 requires a per-circuit trusted setup. For a regulatory context, a compromised setup would allow arbitrary proof forgery with no detection. Production deployment requires a Powers of Tau multi-party ceremony (mitigating single-point trust) or migration to a setup-free system (PLONK, Halo2, STARKs). Both add significant operational complexity.

**Circuit update agility.** If the EU changes thresholds (e.g., lower the water limit from 2000 to 1500 L/kg), the entire circuit changes, requiring a new trusted setup. PLONK-based schemes with universal setups would decouple threshold changes from ceremony costs.

**Prover hardware requirements.** Real outer Groth16 proving over BW6-761 requires tens of gigabytes of RAM and minutes of compute per proof. This is unsuitable for an on-premise manufacturer running modest hardware. GPU-accelerated proving or outsourced proving services would be required — introducing a new trust surface.

**Multi-tier chains.** Real supply chains have more than two tiers (mine → refiner → precursor chemist → cell manufacturer → pack integrator). Each additional tier requires another recursive wrapper. The 2-chain (BLS12-377 → BW6-761) supports one level of recursion; deeper chains need a cycle of curves (e.g., Pallas/Vesta for Nova-style folding) or a different accumulation scheme.

**Revocation.** If a supplier's data is later found fraudulent, there is no mechanism to revoke issued proofs. A commitment registry or nullifier scheme would be needed.

---

## 8. Extensibility to Different Supply Chains

The architecture is designed to be claim- and sector-agnostic. Extending it to a new supply chain requires:

**Adding a new claim** (e.g., `UltraEfficient`, `Recycled80pct`, `ConflictFree`):
1. Add a variant to the `Claim` enum in `types.rs`
2. Implement `to_code()`, `water_max()`, `recycled_min()`, `efficiency_min()` for the new variant
3. The circuits are parameterized by `Claim` — no R1CS changes needed for threshold-based claims

**Changing the sector** (e.g., solar panels, rare-earth magnets):
1. Replace `SupplierSecret` fields with sector-relevant private inputs
2. Replace threshold constants in `SupplierCircuit::generate_constraints`
3. Replace `ManufacturerSecret` fields with sector-relevant private inputs
4. Update `ManufacturerCircuit` constraints accordingly
5. The proof chain, serialization, HTTP API, and CLI are unchanged

**Adding a third tier** (e.g., miner → refiner → manufacturer):
1. Implement a `RefinerCircuit` over BW6-761 that recursively verifies the supplier's Proof₁ (over BLS12-377)
2. Implement a `ManufacturerCircuit` over a third curve that recursively verifies the refiner's proof
3. This requires a three-curve chain; Arkworks supports BLS12-381 / BW6-767 as an alternative outer layer, though documentation is sparse

The primary extensibility cost is the trusted setup ceremony per circuit variant. For a production system with many claim types and tiers, a universal SNARK (PLONK, Halo2) would reduce this to a single setup shared across all circuits.

---

## 9. Proof of Concept Code

### 9.1 Proof Generation (Supplier — real Groth16)

From [crates/zkp-core/src/prove.rs](crates/zkp-core/src/prove.rs):

```rust
pub fn prove_supplier(
    pk: &InnerProvingKey,
    batch_id: BatchId,
    claim: Claim,
    secret: SupplierSecret,
) -> anyhow::Result<InnerProof> {
    let circuit = SupplierCircuit::new(
        batch_id.0,
        claim,
        secret.water_liters_per_kg,
        secret.recycled_content_pct,
    );
    let mut rng = ChaCha20Rng::from_entropy();
    Groth16::<InnerCurve>::prove(pk, circuit, &mut rng)
        .map_err(|e| anyhow::anyhow!("supplier prove failed: {:?}", e))
}
```

The `SupplierCircuit` implements `ConstraintSynthesizer<InnerFr>`, encoding the threshold checks as R1CS constraints. If the witness values violate the thresholds (e.g., `water > 2000`), the circuit is unsatisfiable and `Groth16::prove` returns an error — **no valid proof can be produced for false claims**.

The circuit's `generate_constraints` (from [crates/zkp-core/src/supplier_circuit.rs](crates/zkp-core/src/supplier_circuit.rs)):

```rust
// water <= water_max  →  (water_max - water) must fit in 32 bits
let water_diff = water_max - &water_var;
enforce_non_negative(cs.clone(), &water_diff, 32)?;

// recycled >= recycled_min  →  (recycled - recycled_min) must fit in 32 bits
let recycled_diff = &recycled_var - recycled_min;
enforce_non_negative(cs.clone(), &recycled_diff, 32)?;
```

Range enforcement via bit decomposition (from the same file):

```rust
fn enforce_non_negative(
    _cs: ConstraintSystemRef<InnerFr>,
    val: &FpVar<InnerFr>,
    bit_len: usize,
) -> Result<(), SynthesisError> {
    let bits = val.to_bits_le()?;
    for bit in bits.iter().skip(bit_len) {
        bit.enforce_equal(&Boolean::FALSE)?;
    }
    Ok(())
}
```

### 9.2 Proof Verification (EU Regulator — inner circuit)

```rust
pub fn verify_supplier(
    vk: &InnerVerifyingKey,
    proof: &InnerProof,
    public_inputs: &[InnerFr],
) -> anyhow::Result<bool> {
    Groth16::<InnerCurve>::verify(vk, public_inputs, proof)
        .map_err(|e| anyhow::anyhow!("supplier verify failed: {:?}", e))
}
```

This is a real pairing check. `public_inputs` contains `[InnerFr::from(batch_id), InnerFr::from(claim_code)]`. The verifier has no access to the private witness values — it only learns that they satisfy the constraints.

### 9.3 Proof Composition (Manufacturer — native validation with recursive circuit defined)

Native binding checks in `prove_manufacturer` (from [crates/zkp-core/src/prove.rs](crates/zkp-core/src/prove.rs)):

```rust
// 1. Verify inner proof is valid
let valid = verify_supplier(&inner_vk, &inner_proof, &inner_public_inputs)?;
if !valid { return Err(anyhow::anyhow!("inner proof is invalid")); }

// 2. Batch ID binding — the core anti-proof-swap check
if inner_public_inputs[0] != InnerFr::from(batch_id.0) {
    return Err(anyhow::anyhow!("batch_id mismatch: proof was issued for a different batch"));
}

// 3. Manufacturer threshold
if secret.assembly_efficiency_pct < claim.efficiency_min() {
    return Err(anyhow::anyhow!("manufacturer efficiency {} is below threshold {}", ...));
}
```

The recursive R1CS implementation of the same checks in `ManufacturerCircuit` (from [crates/zkp-core/src/manufacturer_circuit.rs](crates/zkp-core/src/manufacturer_circuit.rs)):

```rust
// Recursive verification: inner Groth16 proof is valid for the bound inputs
let is_valid =
    <Groth16VerifierGadget<InnerCurve, InnerPairingVar> as SNARKGadget<
        InnerFr,
        OuterFr,
        ark_groth16::Groth16<InnerCurve>,
    >>::verify(&vk_var, &input_var, &proof_var)?;
is_valid.enforce_equal(&Boolean::constant(true))?;

// Efficiency threshold: (efficiency − 70) must be non-negative (32-bit range)
let eff_diff = &efficiency_var - &eff_min;
enforce_range_bits(&eff_diff, 32)?;
```

**Current status**: `ManufacturerCircuit::generate_constraints` compiles and is correct. It is not yet called by `prove_manufacturer` — that function performs the same checks natively and returns a mock zero-element proof. The next engineering task is wiring `Groth16::<OuterCurve>::prove(outer_pk, manufacturer_circuit, &mut rng)` into the proving path.

### 9.4 Running the Demo

```bash
# Build everything
cargo build --release

# Terminal 1 — supplier (generates real Groth16 Proof₁ on startup)
cargo run --release -p supplier-service

# Terminal 2 — manufacturer
cargo run --release -p manufacturer-service

# Terminal 3 — EU verifier (five scenarios)
./demo/scripts/demo_valid.sh           # ✔ VALID — happy path
./demo/scripts/demo_invalid_claim.sh   # ✗ supplier data fails threshold → no Proof₁ issued
./demo/scripts/demo_proof_swap.sh      # ✗ manufacturer swaps batch → batch_id mismatch
./demo/scripts/demo_manufacturer_fail.sh # ✗ manufacturer efficiency 60% < 70% threshold
./demo/scripts/demo_forge.sh           # ✗ tampered proof hex rejected at deserialization
```

---

*Built in 18 hours at HackSummit Builder Challenge — April 22–23, 2026 · Lausanne.*
*Work Package 3: "Prove It's Green Without Sharing Secrets" — co-designed with SICPA.*
