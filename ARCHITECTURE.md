# PROVE — ZKP-Chained Battery Passport

**HackSummit Builder Challenge 2026 · Work Package 3 · Powered by SICPA**

A privacy-preserving verification system for EU Battery Regulation compliance, using **chained zero-knowledge proofs** to verify sustainability claims across a lithium supply chain — without revealing any party's commercial secrets.

---

## The Problem

Under the EU Battery Regulation, batteries must prove lifecycle-wide sustainability: where the lithium was mined, how much water was used, whether it's recycled content, how efficiently it was assembled. But this data is split across the supply chain, and every party holds commercially sensitive information they cannot share:

- **Suppliers** know how lithium was sourced (water usage, region, recycled content)
- **Manufacturers** know how efficiently it was used in assembly
- **Regulators (EU)** need to verify end-to-end claims without accessing any of it

Today, this verification relies on paper trails, self-attestation, and periodic audits. It is slow, opaque, and easy to game.

## The Solution

A **chained ZKP protocol** where:

1. The supplier generates a proof that their lithium batch meets sustainability thresholds — without revealing the underlying data.
2. The manufacturer generates a second proof that *verifies the supplier's proof* **and** proves their own assembly data meets standards — without revealing either.
3. The EU verifies a single proof and learns the complete sustainability story for a specific battery, with cryptographic certainty and zero secret disclosure.

The critical design choice: a `batch_id` derived from the physical lithium shipment (SICPA-style authentication) anchors the entire chain. It cryptographically binds the supplier's proof to the specific batch used by the manufacturer, preventing proof-swapping attacks where a manufacturer might reuse a greener supplier's certification.

---

## How Verification Works

```
BATTERY (physical)
  tag contains: batch_id (public, readable)

MANUFACTURER (holds privately)
  For each batch_id:
    - Proof₁ received from supplier
    - own manufacturing data

  ─────── verification begins ───────

1. EU scans battery
   reads: batch_id

2. EU → Manufacturer
   sends: { batch_id, claim, nonce }

3. Manufacturer looks up internal records
   retrieves: Proof₁, own_data (both keyed by batch_id)

4. Manufacturer runs proving circuit
   circuit enforces:
     - Verify(Proof₁) returns true                    ✓
     - Proof₁.batch_id == request.batch_id            ✓  ← the binding
     - own_data satisfies the requested claim         ✓
     - nonce bound to output                          ✓
   generates: Proof₂

5. Manufacturer → EU
   sends: Proof₂

6. EU verifies Proof₂ locally
   result: VALID / INVALID
```

The `batch_id` is the thread that stitches the two proofs together. The supplier commits to it as a public input when generating `Proof₁`, making it cryptographically bound to that specific proof. When the manufacturer builds `Proof₂`, the circuit enforces that the batch_id inside `Proof₁` equals the batch_id the EU asked about. A manufacturer attempting to substitute a different supplier's proof would trigger a mismatch, and no valid `Proof₂` could be generated.

---

## Architecture

### Three Services, One Shared Crate

```
prove-hackathon/
├── Cargo.toml                    # workspace manifest
├── crates/
│   ├── zkp-core/                 # shared library: circuits, proof gen/verify
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── supplier_circuit.rs     # Circuit for Proof₁
│   │   │   ├── manufacturer_circuit.rs # Circuit for Proof₂ (verifies Proof₁)
│   │   │   ├── types.rs                # BatchId, Claim, Proof wrappers
│   │   │   ├── setup.rs                # Trusted setup (mock for hackathon)
│   │   │   └── serialization.rs        # Proof (de)serialization
│   │   └── Cargo.toml
│   │
│   ├── supplier-service/         # Axum server · port 3001
│   │   ├── src/main.rs
│   │   └── Cargo.toml
│   │
│   ├── manufacturer-service/     # Axum server · port 3002
│   │   ├── src/main.rs
│   │   └── Cargo.toml
│   │
│   └── verifier-cli/             # The EU — CLI tool
│       ├── src/main.rs
│       └── Cargo.toml
│
├── demo/
│   ├── scripts/
│   │   ├── demo_valid.sh              # Happy path
│   │   ├── demo_invalid_claim.sh      # Supplier data fails threshold
│   │   ├── demo_proof_swap.sh         # Manufacturer tries to swap proofs
│   │   ├── demo_manufacturer_fail.sh  # Manufacturer data fails threshold
│   │   └── demo_forge.sh              # Tampered Proof₂ fails at the verifier
│   └── fixtures/                      # pre-computed test data
│
└── README.md
```

### What Each Component Does

**`zkp-core`** — the cryptographic heart of the project. Defines the two R1CS circuits, handles the trusted setup, and exposes a clean API for the services to call. All cryptographic logic lives here so the services stay thin.

**`supplier-service`** — simulates a lithium supplier. Axum server on port 3001 that issues `Proof₁` for pre-configured batches on startup. For the demo, it holds three batches: a clean one (`0x42`), a dirty one (`0x99`) that cannot be certified, and a second clean one (`0xAB`) from a different supplier used to demonstrate the proof-swap attack.

**`manufacturer-service`** — simulates a battery manufacturer. Axum server on port 3002 that stores `Proof₁`s received from the supplier, indexed by `batch_id`. When the EU requests verification, it generates `Proof₂` on demand using its internal records and the received challenge.

**`verifier-cli`** — simulates the EU verifier. A command-line tool that scans a battery (reads a `batch_id`), sends a verification request to the manufacturer, and verifies the returned proof locally. Prints colored, clear output for demo narration.

---

## Technology Stack

### Core ZKP Stack: Arkworks

The **Arkworks** Rust ecosystem handles all cryptographic primitives:

| Crate | Purpose |
|---|---|
| `ark-groth16` | Groth16 proving system — small proofs, fast verification |
| `ark-bls12-377` | **Inner** curve (Proof₁). Pairing-friendly, 128-bit security. |
| `ark-bw6-761` | **Outer** curve (Proof₂). Its scalar field equals BLS12-377's base field — the property that makes in-circuit Groth16 verification tractable. |
| `ark-r1cs-std` | Standard gadgets for building constraint systems |
| `ark-relations` | R1CS (Rank-1 Constraint System) framework |
| `ark-snark` | Generic SNARK traits |
| `ark-crypto-primitives` | Poseidon sponge + **SNARK verifier gadget** for recursion |

**Why Arkworks:** Pure Rust, production-grade, used by real ZK projects (Aleo, Espresso, Penumbra). Critically, it provides a **SNARK verifier gadget** that lets you verify `Proof₁` inside the circuit for `Proof₂` — the mechanism that makes proof chaining possible.

**Why Groth16 over alternatives:** Tiny proofs (~200–500 bytes), millisecond verification, mature tooling. The trusted setup is acceptable for a hackathon; production would use a Powers of Tau ceremony or migrate to PLONK/STARKs.

**Why BLS12-377 / BW6-761 rather than a single curve (e.g. BN254):** Recursion — verifying a Groth16 proof *inside* another Groth16 circuit — requires the outer circuit's scalar field to equal the inner curve's base field. BN254 is not in such a pairing-friendly 2-chain with itself; verifying a BN254 proof inside a BN254 circuit would require emulated pairing arithmetic (millions of constraints, proving time in tens of minutes). The BLS12-377 / BW6-761 pair was purpose-built for this use case (Aleo / Zexe) and keeps Proof₂ proving in the seconds-to-tens-of-seconds range. All dependency versions are pinned to arkworks `0.5.0`, the coherent published set.

### Web & Hosting

| Tool | Purpose |
|---|---|
| `axum` | Modern async Rust web framework for the services |
| `tokio` | Async runtime |
| `serde` / `serde_json` | JSON (de)serialization for HTTP bodies |
| `bincode` | Efficient binary serialization for proof payloads |
| `reqwest` | HTTP client for inter-service calls |

### CLI & Demo

| Tool | Purpose |
|---|---|
| `clap` | CLI argument parsing |
| `colored` | Terminal colors (green ✓ for valid, red ✗ for invalid) |
| `indicatif` | Progress bars during proof generation |

### Development

- **Rust 1.75+** (stable)
- `cargo-watch` — auto-rebuild on file save

---

## Installation

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Clone and build
git clone <repo-url>
cd prove-hackathon
cargo build --release

# Install helpers
cargo install cargo-watch
```

---

## Running the Demo

Open three terminals:

```bash
# Terminal 1 — supplier service
cargo run --release -p supplier-service

# Terminal 2 — manufacturer service
cargo run --release -p manufacturer-service

# Terminal 3 — run demo scripts
./demo/scripts/demo_valid.sh
```

On startup, the services automatically:
1. Run the (mock) trusted setup
2. Generate pre-seeded supplier proofs for batch IDs `0x42`, `0x99`, `0xAB`
3. Deliver relevant proofs from supplier to manufacturer (simulating shipment)

After that, the demo scripts run independently.

---

## Demo Scenarios

Five scripts, each illustrating a specific property of the system. Demos 2–4 show **proving-time** soundness (the prover cannot construct a proof for a false statement). Demo 5 shows **verification-time** soundness (a tampered proof is detected by the verifier).

### ✅ Demo 1 — Valid Path (`demo_valid.sh`)

```bash
verifier-cli verify --batch-id 0x42 --claim sustainable
```

- EU requests verification for `batch_id = 0x42` (clean supplier batch)
- Manufacturer has a valid `Proof₁` for `0x42`, and its own data meets the claim
- `Proof₂` is generated, EU verifies → **✅ VALID**

**What this shows:** the happy path. A legitimately sustainable battery can be verified end-to-end in seconds, without either party revealing a single byte of secret data.

### ❌ Demo 2 — Supplier Claim Fails (`demo_invalid_claim.sh`)

```bash
verifier-cli verify --batch-id 0x99 --claim sustainable
```

- EU requests verification for `batch_id = 0x99` (dirty supplier batch)
- Supplier never issued a proof for `0x99` because its data failed thresholds
- Manufacturer has no `Proof₁` on file → **❌ CANNOT PROVE**

**What this shows:** bad data cannot enter the chain in the first place. If the supplier cannot honestly prove their claim, the chain never starts.

### ❌ Demo 3 — Proof-Swap Attack (`demo_proof_swap.sh`)

```bash
# Manufacturer attempts to use Proof₁ from batch 0xAB
# to answer a request for batch 0x42
verifier-cli verify --batch-id 0x42 --claim sustainable --force-swap
```

- Manufacturer tries to cheat: uses a `Proof₁` from a different clean batch (`0xAB`) to answer a request for `0x42`
- The circuit enforces `Proof₁.batch_id == request.batch_id`
- Proof generation fails at the constraint, or produces an invalid `Proof₂` → **❌ INVALID**

**What this shows:** the `batch_id` binding actually works. A manufacturer cannot substitute a greener supplier's proof for a dirtier one.

### ❌ Demo 4 — Manufacturer Data Fails (`demo_manufacturer_fail.sh`)

```bash
verifier-cli verify --batch-id 0x42 --claim ultra-efficient
```

- Valid supplier proof exists for `0x42`, but the manufacturer's own assembly efficiency is below the stricter threshold requested
- Proof generation fails at the manufacturer's own constraints → **❌ CANNOT PROVE**

**What this shows:** both halves of the chain must independently satisfy the claim. A clean supplier does not excuse a sloppy manufacturer.

### ❌ Demo 5 — Forgery on the Wire (`demo_forge.sh`)

```bash
verifier-cli verify --batch-id 0x42 --claim sustainable --force-forge
```

- Manufacturer generates a legitimate `Proof₂` and then (simulating an on-path attacker or a bug-induced mutation) **tampers the proof bytes** before sending
- EU attempts local verification → **❌ INVALID (signature fails)**

**What this shows:** even if a proof reaches the verifier, tampering is detectable. Demos 2–4 show that proofs *cannot be forged at proving time*; demo 5 shows that tampered proofs *are rejected at verification time*. Both classes of fraud are caught.

---

## Implementation Specification

This section nails down the concrete interfaces, constants, and data shapes the four crates must agree on. Treat it as the contract between the teammates building each component.

### Shared Types (`zkp-core::types`)

```rust
pub type InnerCurve      = ark_bls12_377::Bls12_377;
pub type InnerFr         = ark_bls12_377::Fr;          // inner scalar field
pub type InnerFq         = ark_bls12_377::Fq;          // == OuterFr
pub type InnerPairingVar = ark_bls12_377::constraints::PairingVar;
pub type OuterCurve      = ark_bw6_761::BW6_761;
pub type OuterFr         = ark_bw6_761::Fr;            // outer constraint field

pub struct BatchId(pub u64);                           // hex in API ("0x42")
pub enum   Claim   { Sustainable, UltraEfficient }     // kebab-case in API

pub struct SupplierSecret      { water_liters_per_kg: u32, recycled_content_pct: u32 }
pub struct ManufacturerSecret  { assembly_efficiency_pct: u32, energy_kwh_per_cell: u32 }
```

### Threshold Constants (public, hardcoded)

| Claim | `water` max | `recycled` min | `efficiency` min | `energy` max |
|---|---:|---:|---:|---:|
| Sustainable | 2000 L/kg | 10 % | 70 % | n/a |

### Inner Circuit — `SupplierCircuit` (over `InnerFr`)

**Public inputs (order matters — verifier passes them in this order):**
1. `batch_id`  — `InnerFr`
2. `claim_code` — `InnerFr` (`1` = Sustainable, `2` = UltraEfficient)

**Private witnesses:** `water_liters_per_kg`, `recycled_content_pct`.

**Constraints:**
- `claim_code ∈ {1, 2}`
- `water ≤ water_max(claim)`
- `recycled ≥ recycled_min(claim)`
- `batch_id` is a public input (no further check here — binding is enforced in the outer circuit)

### Outer Circuit — `ManufacturerCircuit` (over `OuterFr`)

**Public inputs (EU verifies against these, in order):**
1. `batch_id_requested` — `OuterFr`
2. `claim_code_requested` — `OuterFr`
3. `nonce` — `OuterFr`

**Private witnesses:**
- `inner_proof : Proof<BLS12-377>` (allocated as `ProofVar<InnerCurve, InnerPairingVar>`)
- `inner_vk : VerifyingKey<BLS12-377>` (allocated as `VerifyingKeyVar<InnerCurve, InnerPairingVar>`)
- Inner public inputs as `EmulatedFpVar<InnerFr, OuterFr>`: `[inner_batch_id, inner_claim_code]`
- `assembly_efficiency_pct`, `energy_kwh_per_cell`

**Constraints:**
1. **Recursive verification:**
   `Groth16VerifierGadget::<InnerCurve, InnerPairingVar>::verify(&vk, &inputs, &proof)? == TRUE`
2. **`batch_id` binding (the critical constraint):** allocate `batch_id_requested` as 64 public bits, derive *both* the native outer FpVar and the emulated-inner FpVar from the same bits. This makes `inner_proof.batch_id == batch_id_requested` true by construction (or unsatisfiable if the prover tries to use a mismatched inner proof).
3. **`claim_code` binding:** same bit-sharing trick (8 bits).
4. **Manufacturer threshold:** `efficiency ≥ eff_min(claim)`; when `claim == UltraEfficient` also `energy ≤ ENERGY_MAX_ULTRA`.
5. **Nonce binding:** `nonce` is allocated as a public input and used in a trivial but non-eliminable constraint so it cannot be optimized away.

### Setup (`zkp-core::setup`)

```rust
pub struct SetupArtifacts {
    pub inner_pk: ProvingKey<InnerCurve>, pub inner_vk: VerifyingKey<InnerCurve>,
    pub outer_pk: ProvingKey<OuterCurve>, pub outer_vk: VerifyingKey<OuterCurve>,
}
pub fn load_or_generate(keys_dir: &Path) -> anyhow::Result<SetupArtifacts>;
```

On first boot, runs `Groth16::<C>::setup` for both layers with dummy circuits and writes compressed bytes to `data/keys/{inner,outer}_{pk,vk}.bin`. On subsequent boots, deserializes from disk. The outer setup is the slow step (~30–90 s on a laptop); do not re-run it per `cargo run`.

### HTTP API — `supplier-service` (port 3001)

| Method | Path | Body / Response |
|---|---|---|
| `GET`  | `/health`   | `{"status":"ok"}` |
| `GET`  | `/vk`       | inner VK, hex-encoded |
| `POST` | `/proof1`   | req: `{"batch_id":"0x42"}` → resp: `{"proof":"<hex>","public_inputs":{"batch_id":"0x42","claim":"sustainable"}}` or `404` |

**Startup behaviour:** runs setup, attempts to prove the three pre-seeded batches (`0x42` clean, `0x99` dirty — prover fails, logged, stored `None`, `0xAB` clean), then POSTs the two valid `Proof₁`s to `http://localhost:3002/ingest`.

### HTTP API — `manufacturer-service` (port 3002)

| Method | Path | Body / Response |
|---|---|---|
| `GET`  | `/health`     | `{"status":"ok"}` |
| `GET`  | `/vk_outer`   | outer VK, hex-encoded (verifier-cli caches this) |
| `POST` | `/ingest`     | `{"batch_id","proof","claim"}` — supplier pushes a `Proof₁` |
| `POST` | `/verify`     | `{"batch_id","claim","nonce","force_swap":bool,"force_forge":bool}` → `{"proof2":"<hex>","public_inputs":{...}}` on success, else structured error (404 / 422) |

Store: `Arc<RwLock<HashMap<BatchId, StoredProof1>>>`.
`force_swap=true`: look up Proof₁ under a *different* batch_id than the one requested (triggers the binding constraint, outer R1CS unsat).
`force_forge=true`: generate Proof₂ normally, then flip a byte before shipping (triggers verification failure at the EU).

### CLI — `verifier-cli`

```
verifier-cli verify --batch-id <hex> --claim <sustainable|ultra-efficient>
                    [--force-swap] [--force-forge]
                    [--manufacturer-url http://localhost:3002]
```

Generates a random 32-byte nonce, POSTs `/verify`, caches the outer VK on first run, verifies `Proof₂` locally with `Groth16::<OuterCurve>::verify`, prints colored result (✅ / ❌) with an `indicatif` spinner during the request.

### Failure-Mode Matrix (exact behaviour per demo)

| Demo | Where it fails | Mechanism | HTTP | CLI output |
|---|---|---|---|---|
| 1. Valid | — | Proof₂ verifies | 200 | `✅ VALID` |
| 2. Supplier fails (`0x99`) | Supplier's prover at boot | inner R1CS unsat → `SynthesisError::Unsatisfiable` — **Proof₁ never produced** | 404 | `❌ CANNOT PROVE` |
| 3. Proof swap (`--force-swap`) | Manufacturer's outer prover | `inner_batch_id ≠ batch_id_requested` → outer R1CS unsat — **Proof₂ never produced** | 422 | `❌ INVALID (swap detected)` |
| 4. Manufacturer fails | Manufacturer's outer prover | efficiency threshold unsat — **Proof₂ never produced** | 422 | `❌ CANNOT PROVE` |
| 5. Forgery (`--force-forge`) | EU's local verifier | proof bytes mutated in transit | 200 | `❌ INVALID (verify rejects)` |

### Workspace Layout and Ownership

| Crate / path | What it owns | Critical files |
|---|---|---|
| `crates/zkp-core` | All cryptographic logic | `types.rs`, `supplier_circuit.rs`, `manufacturer_circuit.rs`, `setup.rs`, `serialization.rs` |
| `crates/supplier-service` | Axum server on :3001, pre-seeds and emits Proof₁ | `src/main.rs` |
| `crates/manufacturer-service` | Axum server on :3002, ingests Proof₁, generates Proof₂ | `src/main.rs` |
| `crates/verifier-cli` | CLI, calls manufacturer, verifies locally | `src/main.rs` |
| `demo/scripts/` | 5 bash scripts (one per scenario) | `demo_{valid,invalid_claim,proof_swap,manufacturer_fail,forge}.sh` |
| `data/keys/` | Serialized proving/verifying keys (gitignored) | regenerated on first boot |

### Dependency Pin Set (arkworks 0.5.0, known-composable)

The workspace `[workspace.dependencies]` already pins every arkworks sibling at `0.5`. Do not mix master-branch deps — they are not compatible with the published 0.5.0 set. The `r1cs` feature on `ark-bls12-377` is required (it's what exposes `ark_bls12_377::constraints::PairingVar`). The `r1cs` + `sponge` + `snark` features on `ark-crypto-primitives` are required for the verifier gadget.

---

## Security Model & Limitations

### What the System Guarantees

- **Soundness:** if a proof verifies, the underlying claims are true (with overwhelming probability — breaking this requires breaking the underlying cryptography).
- **Zero-knowledge:** no secret data from any party is revealed during verification.
- **Proof binding:** the `batch_id` is committed as a public input inside both proofs. A manufacturer cannot detach a valid proof and reuse it with a different batch_id.
- **Freshness:** the nonce in each verification request prevents replay of cached proofs.

### What It Does Not Guarantee

- **Physical-to-digital binding:** nothing in the protocol prevents a manufacturer from *physically* mislabeling a battery (applying batch `0x42`'s tag to a battery made from different lithium). This requires a physical anchor — **which is exactly where SICPA's tamper-resistant authentication technology fits in**.
- **Mass-balance fraud:** a manufacturer could attempt to certify more batteries than a batch's lithium can physically produce. Mitigated by publishing batch commitments with mass bounds and by regulatory audit.
- **Trusted setup:** Groth16 requires a setup ceremony. A compromised setup would allow proof forgery. Production deployments would use a Powers of Tau ceremony or migrate to setup-free schemes (PLONK, STARKs).

### The Honest Framing

> *This system does not eliminate fraud. It makes fraud detectable, attributable, and expensive — which is what regulation actually needs.*

The protocol reduces the attack surface from "trust every document in the supply chain" to "trust one physical authentication moment at material handoff" — exactly where SICPA already operates.

---

## Roadmap (Post-Hackathon)

- **Physical anchor:** integrate with a SICPA-style physical tag for `batch_id` derivation
- **Mass-balance constraints:** add circuit constraints bounding batteries-per-batch to the physical lithium quantity
- **Setup-free migration:** port to PLONK or STARKs to eliminate trusted setup risk
- **Multi-tier chains:** extend to three+ actors (mine → refiner → manufacturer → integrator)
- **Verifiable Credentials:** wrap proofs in W3C Verifiable Credentials for interoperability with existing EU digital identity infrastructure
- **On-device verification:** WASM-compile the verifier for smartphone verification by end consumers

---

## Team & Credits

Built in 18 hours at the **HackSummit Builder Challenge** — April 22–23, 2026 · Lausanne.

Work Package 3: *Prove It's Green Without Sharing Secrets* — co-designed with **SICPA**.

---

## License

MIT — everything in this repository is yours to use.
