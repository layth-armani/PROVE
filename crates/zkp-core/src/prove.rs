use ark_ec::{pairing::Pairing, AffineRepr};
use ark_groth16::Groth16;
use ark_snark::SNARK;
use ark_std::rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use crate::supplier_circuit::SupplierCircuit;
use crate::types::{
    BatchId, Claim, InnerCurve, InnerFr, InnerProof, InnerProvingKey, InnerVerifyingKey,
    ManufacturerSecret, OuterCurve, OuterFr, OuterProof, OuterVerifyingKey,
    SupplierSecret,
};

/// Produce the public-input vector for the supplier (inner) circuit, in the
/// order the verifier expects.
pub fn supplier_public_inputs(batch_id: BatchId, claim: Claim) -> Vec<InnerFr> {
    vec![InnerFr::from(batch_id.0), InnerFr::from(claim.to_code())]
}

/// Produce the public-input vector for the manufacturer (outer) circuit.
pub fn manufacturer_public_inputs(batch_id: BatchId, claim: Claim, nonce: u64) -> Vec<OuterFr> {
    vec![
        OuterFr::from(batch_id.0),
        OuterFr::from(claim.to_code()),
        OuterFr::from(nonce),
    ]
}

/// Generate Proof₁. Returns `Err` if the secret does not satisfy the claim
/// (the R1CS is unsatisfiable → no proof can be produced).
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

pub fn verify_supplier(
    vk: &InnerVerifyingKey,
    proof: &InnerProof,
    public_inputs: &[InnerFr],
) -> anyhow::Result<bool> {
    Groth16::<InnerCurve>::verify(vk, public_inputs, proof)
        .map_err(|e| anyhow::anyhow!("supplier verify failed: {:?}", e))
}

/// Mock manufacturer proof: validates all constraints natively in Rust.
/// Returns a deterministic proof structure when valid; Err when any check fails.
pub fn prove_manufacturer(
    batch_id: BatchId,
    claim: Claim,
    _nonce: u64,
    inner_proof: InnerProof,
    inner_vk: InnerVerifyingKey,
    inner_public_inputs: Vec<InnerFr>,
    secret: ManufacturerSecret,
) -> anyhow::Result<OuterProof> {
    // 1. Verify inner proof is valid
    let valid = verify_supplier(&inner_vk, &inner_proof, &inner_public_inputs)
        .map_err(|e| anyhow::anyhow!("inner proof verification failed: {}", e))?;
    if !valid {
        return Err(anyhow::anyhow!("inner proof is invalid"));
    }

    // 2. Batch ID binding
    if inner_public_inputs.is_empty() {
        return Err(anyhow::anyhow!("inner_public_inputs is empty"));
    }
    if inner_public_inputs[0] != InnerFr::from(batch_id.0) {
        return Err(anyhow::anyhow!("batch_id mismatch: proof was issued for a different batch"));
    }

    // 3. Claim code binding
    if inner_public_inputs.len() < 2 {
        return Err(anyhow::anyhow!("inner_public_inputs missing claim_code"));
    }
    if inner_public_inputs[1] != InnerFr::from(claim.to_code()) {
        return Err(anyhow::anyhow!("claim_code mismatch"));
    }

    // 4. Manufacturer threshold
    if secret.assembly_efficiency_pct < claim.efficiency_min() {
        return Err(anyhow::anyhow!(
            "manufacturer efficiency {} is below threshold {}",
            secret.assembly_efficiency_pct,
            claim.efficiency_min()
        ));
    }

    // 5. All checks passed — return a mock proof (zero group elements).
    //    When serialized, this produces a fixed-size byte sequence that
    //    the verifier can deserialize to confirm the proof is well-formed.
    use ark_groth16::Proof;
    let mock_proof = Proof {
        a: <OuterCurve as Pairing>::G1Affine::zero(),
        b: <OuterCurve as Pairing>::G2Affine::zero(),
        c: <OuterCurve as Pairing>::G1Affine::zero(),
    };
    Ok(mock_proof)
}

/// Mock verifier: always returns true if proof deserializes correctly.
/// Real tamper-detection happens in the CLI via proof_from_hex().
pub fn verify_manufacturer(
    _vk: &OuterVerifyingKey,
    _proof: &OuterProof,
    _public_inputs: &[OuterFr],
) -> anyhow::Result<bool> {
    Ok(true)
}
