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

1. The supplier generates **Proof₁** that their lithium batch meets sustainability thresholds — without revealing the underlying data.
2. The manufacturer generates **Proof₂** that *recursively verifies Proof₁* **and** proves their own assembly data meets standards — without revealing either.
3. The EU verifies a single proof (Proof₂) and learns the complete sustainability story for a specific battery, with cryptographic certainty and zero secret disclosure.

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

### Four Crates, One Workspace

```
PROVE/
├── Cargo.toml                      # workspace manifest & deps
├── crates/
│   ├── zkp-core/                   # shared crypto library
│   │   ├── src/
│   │   │   ├── lib.rs              # module exports
│   │   │   ├── types.rs            # BatchId, Claim, Proof aliases
│   │   │   ├── supplier_circuit.rs # SupplierCircuit (Proof₁)
│   │   │   ├── manufacturer_circuit.rs # ManufacturerCircuit (Proof₂, recursive)
│   │   │   ├── prove.rs            # prove_supplier, prove_manufacturer, verify_*
│   │   │   ├── setup.rs            # load_or_generate trusted setup artifacts
│   │   │   └── serialization.rs    # hex (de)serialization for proofs & VKs
│   │   └── Cargo.toml
│   │
│   ├── supplier-service/           # Axum server · port 3001
│   │   ├── src/main.rs             # /health, /vk, /proof1, async ingest ship-to-mfg
│   │   └── Cargo.toml
│   │
│   ├── manufacturer-service/       # Axum server · port 3002
│   │   ├── src/main.rs             # /health, /vk_outer, /ingest, /verify
│   │   └── Cargo.toml
│   │
│   └── verifier-cli/               # EU verifier — CLI tool
│       ├── src/main.rs             # `verify --batch-id <hex> --claim <claim>`
│       └── Cargo.toml
│
├── demo/
│   └── scripts/
│       ├── demo_valid.sh           # Demo 1: happy path (0x42)
│       ├── demo_invalid_claim.sh   # Demo 2: supplier fails threshold (0x99)
│       ├── demo_proof_swap.sh      # Demo 3: manufacturer cheats (--force-swap)
│       ├── demo_manufacturer_fail.sh # Demo 4: mfg data fails (0xCD)
│       └── demo_forge.sh           # Demo 5: tampering on wire (--force-forge)
│
├── data/
│   └── keys/                       # generated on first boot (gitignored)
│       ├── inner_pk.bin, inner_vk.bin
│       └── outer_pk.bin, outer_vk.bin
│
├── ARCHITECTURE.md
├── README.md
└── Cargo.lock
```

### What Each Component Does

**`zkp-core`** — The cryptographic heart. Defines the two R1CS circuits (`SupplierCircuit` over BLS12-377, `ManufacturerCircuit` over BW6-761), exposes clean proving/verification APIs, handles trusted setup, and provides hex serialization. All circuit logic and threshold constants live here.

**`supplier-service`** (port 3001) — Simulates a lithium supplier. On startup:
- Runs trusted setup (or loads from `data/keys/`)
- Pre-seeds four batches with supplier secrets: `0x42` (clean), `0x99` (dirty), `0xAB` (clean), `0xCD` (clean)
- Generates Proof₁ for each; stores successful ones
- Attempts to ship valid proofs to the manufacturer via HTTP POST `/ingest`

HTTP endpoints:
- `GET /health` → `{"status":"ok"}`
- `GET /vk` → inner verifying key (hex)
- `POST /proof1` → `{ batch_id } → { proof, public_inputs }`

**`manufacturer-service`** (port 3002) — Simulates a battery manufacturer. On startup:
- Loads trusted setup artifacts (reuses the same keys)
- Pre-seeds three batches with manufacturer secrets: `0x42` (efficient, 85%), `0xAB` (efficient, 80%), `0xCD` (inefficient, 60%)

HTTP endpoints:
- `GET /health` → `{"status":"ok"}`
- `GET /vk_outer` → outer verifying key (hex)
- `POST /ingest` → stores `{ batch_id, proof, claim }` from supplier
- `POST /verify` → `{ batch_id, claim, nonce, force_swap?, force_forge? } → { proof2, public_inputs }`
  - Normal case: generates Proof₂ using stored Proof₁ for the requested batch
  - `force_swap=true`: uses Proof₁ from a *different* batch → circuit unsatisfiable
  - `force_forge=true`: mutates proof bytes → verification fails

**`verifier-cli`** — The EU verifier (command-line). Usage:
```bash
verifier-cli verify --batch-id 0x42 --claim sustainable [--force-swap] [--force-forge]
```
On each run:
- Parses batch_id and claim
- Generates a fresh 64-bit nonce
- Fetches outer VK from manufacturer (cached in `data/keys/outer_vk.hex`)
- POSTs a verify request and receives Proof₂
- Locally verifies Proof₂ using `Groth16::verify`
- Prints colored result: ✔ VALID or ✗ INVALID

---

## Technology Stack

### Core ZKP: Arkworks 0.5.0 (pinned coherent set)

| Crate | Purpose |
|---|---|
| `ark-groth16` | Groth16 proving system — small proofs, fast verification |
| `ark-bls12-377` | **Inner curve** for Proof₁. Pairing-friendly, 128-bit security. |
| `ark-bw6-761` | **Outer curve** for Proof₂. Scalar field = BLS12-377 base field → recursive verification tractable. |
| `ark-r1cs-std` | R1CS constraint gadgets (FpVar, Boolean, field operations) |
| `ark-relations` | Rank-1 Constraint System framework |
| `ark-crypto-primitives` | SNARK verifier gadget (Groth16VerifierGadget) for in-circuit proof verification |

**Why this stack:**
- Pure Rust, production-grade (Aleo, Espresso, Penumbra)
- Groth16: tiny proofs (~500 bytes), millisecond verification, mature
- BLS12-377 / BW6-761: purpose-built for proof recursion — only pairing-friendly 2-chain where inner scalar field = outer base field
- Setup is acceptable for hackathon; production would use Powers of Tau or PLONK/STARKs

### Web & Async

| Tool | Purpose |
|---|---|
| `axum` | Modern async web framework for the services |
| `tokio` | Async runtime (full features) |
| `serde` / `serde_json` | JSON serialization for HTTP bodies |
| `reqwest` | HTTP client (rustls, no native TLS) |

### CLI & Demo

| Tool | Purpose |
|---|---|
| `clap` | CLI argument parsing (derive macros) |
| `colored` | Terminal colors (✔ green, ✗ red) |
| `indicatif` | Spinner during async proof requests |

---

## Running the Demo

### Build
```bash
cargo build --release
```

### Start Services (three terminals)

```bash
# Terminal 1 — supplier (port 3001)
cargo run --release -p supplier-service

# Terminal 2 — manufacturer (port 3002)
cargo run --release -p manufacturer-service

# Terminal 3 — run demos
./demo/scripts/demo_valid.sh
```

### Demo Scripts (Five Scenarios)

Each script showcases a different property of the system:

#### ✔ Demo 1 — Valid Path (`demo_valid.sh`)

```bash
verifier-cli verify --batch-id 0x42 --claim sustainable
```

- `0x42` has a clean supplier Proof₁ and clean manufacturer data
- Proof₂ is generated successfully
- EU verification returns **VALID** ✔

**What this shows:** the happy path. A legitimately sustainable battery can be verified end-to-end in seconds, with zero secret disclosure.

#### ✗ Demo 2 — Supplier Claim Fails (`demo_invalid_claim.sh`)

```bash
verifier-cli verify --batch-id 0x99 --claim sustainable
```

- Supplier data for `0x99`: water 3000 L/kg, recycled 5% → both fail thresholds (max 2000, min 10)
- Supplier never issued a Proof₁ for `0x99`
- Manufacturer has no proof on file → **CANNOT PROVE (404)** ✗

**What this shows:** bad data cannot enter the system. If the supplier cannot honestly prove, the chain never starts.

#### ✗ Demo 3 — Proof-Swap Attack (`demo_proof_swap.sh`)

```bash
verifier-cli verify --batch-id 0x42 --claim sustainable --force-swap
```

- Manufacturer attempts to use Proof₁ from `0xAB` (a different supplier's clean batch) to answer a request for `0x42`
- The outer circuit enforces: `inner_proof.batch_id == batch_id_requested` (via bit-sharing)
- This constraint cannot be satisfied with mismatched batches → Proof₂ generation fails
- Manufacturer returns **UNPROCESSABLE_ENTITY (422)** ✗

**What this shows:** the batch_id binding actually works. Proof-swapping is mathematically impossible.

#### ✗ Demo 4 — Manufacturer Data Fails (`demo_manufacturer_fail.sh`)

```bash
verifier-cli verify --batch-id 0xCD --claim sustainable
```

- Supplier Proof₁ for `0xCD` is valid (water 700 L/kg, recycled 40%)
- But manufacturer's assembly efficiency for `0xCD` is 60% (< 70% threshold)
- Proof₂ generation fails at the manufacturer's own constraint
- Manufacturer returns **UNPROCESSABLE_ENTITY (422)** ✗

**What this shows:** both halves of the chain must independently satisfy the claim. A clean supplier does not excuse a sloppy manufacturer.

#### ✗ Demo 5 — Forgery on the Wire (`demo_forge.sh`)

```bash
verifier-cli verify --batch-id 0x42 --claim sustainable --force-forge
```

- Manufacturer generates a legitimate Proof₂, then **flips a byte** before shipping (simulating tampering or a bug)
- EU attempts local verification → proof bytes are invalid
- Groth16 verification rejects → **INVALID (verify rejects)** ✗

**What this shows:** tampering is detected at verification time. Demos 2–4 show proofs *cannot be forged at proving time* (R1CS unsatisfiable); demo 5 shows *tampered proofs are rejected at verification time*. Both attack classes are caught.

---

## Implementation Specification

### Shared Types (`zkp-core::types`)

```rust
pub type InnerCurve = Bls12_377;
pub type InnerFr = ark_bls12_377::Fr;
pub type OuterCurve = BW6_761;
pub type OuterFr = ark_bw6_761::Fr;

pub struct BatchId(pub u64);  // hex in API ("0x42")
pub enum Claim { Sustainable }  // only claim currently supported

pub struct SupplierSecret { water_liters_per_kg: u32, recycled_content_pct: u32 }
pub struct ManufacturerSecret { assembly_efficiency_pct: u32, energy_kwh_per_cell: u32 }
```

### Thresholds (Sustainable claim)

| Metric | Threshold |
|---|---|
| water_liters_per_kg | ≤ 2000 |
| recycled_content_pct | ≥ 10 |
| assembly_efficiency_pct | ≥ 70 |

### Circuits

**SupplierCircuit** (over `InnerFr` / BLS12-377):
- Public inputs: `batch_id`, `claim_code`
- Private witnesses: `water_liters_per_kg`, `recycled_content_pct`
- Constraints: `water ≤ water_max`, `recycled ≥ recycled_min`, claim_code enforcement

**ManufacturerCircuit** (over `OuterFr` / BW6-761):
- Public inputs: `batch_id_requested`, `claim_code_requested`, `nonce`
- Private witnesses:
  - Proof₁ (inner proof as variable)
  - Verifying key for inner circuit
  - Inner public inputs (as emulated field elements)
  - `assembly_efficiency_pct`, `energy_kwh_per_cell`
- Key constraints:
  1. **Recursive verify:** `Groth16VerifierGadget::verify(inner_vk, inner_inputs, inner_proof)` returns true
  2. **batch_id binding:** allocate as 64 bits → reconstruct OuterFr and InnerFr from same bits, enforce equality with public input and inner public input
  3. **claim_code binding:** allocate as 8 bits, same reconstruction + enforcement
  4. **Efficiency threshold:** `efficiency - 70` must be non-negative and fit in 32 bits
  5. **Nonce binding:** `nonce * 1 == nonce` (trivial but non-eliminable)

### Setup

```rust
pub fn load_or_generate(keys_dir: &Path) -> anyhow::Result<SetupArtifacts>
```

On first boot:
- Runs Groth16 setup for `SupplierCircuit` over BLS12-377 → `inner_pk`, `inner_vk`
- Runs Groth16 setup for `ManufacturerCircuit` over BW6-761 → `outer_pk`, `outer_vk` (slow step: ~30–90s)
- Serializes (compressed) to `data/keys/{inner,outer}_{pk,vk}.bin`

On subsequent boots:
- Deserializes from disk (< 1s)

### Proof Serialization

```rust
pub fn proof_to_hex<E: Pairing>(proof: &Proof<E>) -> anyhow::Result<String>
pub fn proof_from_hex<E: Pairing>(s: &str) -> anyhow::Result<Proof<E>>
```

Uses canonical compressed serialization → hex.

---

## Security Model & Limitations

### What the System Guarantees

- **Soundness:** if a proof verifies, the underlying claims are true (cryptographic certainty).
- **Zero-knowledge:** no party's secret data is revealed during verification.
- **Proof binding:** the `batch_id` is committed as a public input inside both proofs. A manufacturer cannot detach a proof and reuse it with a different batch_id.
- **Freshness:** the nonce in each verification request prevents replay of cached proofs.

### What It Does Not Guarantee

- **Physical-to-digital binding:** nothing in the protocol prevents a manufacturer from *physically* mislabeling a battery (applying batch `0x42`'s tag to a battery made from different lithium). This requires a physical anchor — **which is exactly where SICPA's tamper-resistant authentication technology fits in**.
- **Mass-balance fraud:** a manufacturer could attempt to certify more batteries than a batch's lithium can physically produce. Mitigated by publishing batch commitments with mass bounds and by regulatory audit.
- **Trusted setup risk:** Groth16 requires a setup ceremony. A compromised setup would allow proof forgery. Production deployments would use a Powers of Tau ceremony or migrate to setup-free schemes (PLONK, STARKs).

### The Honest Framing

> *This system does not eliminate fraud. It makes fraud detectable, attributable, and expensive — which is what regulation actually needs.*

The protocol reduces the attack surface from "trust every document in the supply chain" to "trust one physical authentication moment at material handoff" — exactly where SICPA already operates.

---

## Development

### Prerequisites

- Rust 1.75+ (stable)
- `cargo` (comes with rustup)

### First Build (includes setup)

```bash
cargo build --release
```

On first run, the supplier and manufacturer services will each:
1. Check `data/keys/` for cached keys
2. If not found, run the trusted setup (~60s per service, parallelizable)
3. Cache keys to disk for future runs

### Watch Mode

```bash
cargo watch -x 'check --workspace'
```

### Run a Single Service

```bash
cargo run --release -p supplier-service
```

---

## Roadmap (Post-Hackathon)

- **Physical anchor:** integrate with a SICPA-style physical tag for `batch_id` derivation
- **Multi-claim support:** add `UltraEfficient`, `Recycled`, etc. claims with per-claim thresholds
- **Mass-balance constraints:** add circuit constraints bounding batteries-per-batch
- **Setup-free migration:** port to PLONK or STARKs to eliminate trusted setup risk
- **Multi-tier chains:** extend to three+ actors (mine → refiner → manufacturer → integrator)
- **Verifiable Credentials:** wrap proofs in W3C VC format for interoperability
- **On-device verification:** WASM-compile the verifier for smartphone verification by consumers

---

## Team & Credits

Built in 18 hours at the **HackSummit Builder Challenge** — April 22–23, 2026 · Lausanne.

Work Package 3: *Prove It's Green Without Sharing Secrets* — co-designed with **SICPA**.

---

## License

MIT — everything in this repository is yours to use.
