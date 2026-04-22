use ark_groth16::Groth16;
use ark_snark::SNARK;
use ark_std::rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use crate::manufacturer_circuit::ManufacturerCircuit;
use crate::supplier_circuit::SupplierCircuit;
use crate::types::{
    BatchId, Claim, InnerCurve, InnerFr, InnerProof, InnerProvingKey, InnerVerifyingKey,
    ManufacturerSecret, OuterCurve, OuterFr, OuterProof, OuterProvingKey, OuterVerifyingKey,
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

/// Generate Proof₂. Returns `Err` if:
///   * the inner proof is invalid, or
///   * the inner batch_id/claim_code don't match the requested ones, or
///   * the manufacturer's data doesn't satisfy the threshold.
#[allow(clippy::too_many_arguments)]
pub fn prove_manufacturer(
    pk: &OuterProvingKey,
    batch_id: BatchId,
    claim: Claim,
    nonce: u64,
    inner_proof: InnerProof,
    inner_vk: InnerVerifyingKey,
    inner_public_inputs: Vec<InnerFr>,
    secret: ManufacturerSecret,
) -> anyhow::Result<OuterProof> {
    let circuit = ManufacturerCircuit::new(
        batch_id,
        claim,
        nonce,
        inner_proof,
        inner_vk,
        inner_public_inputs,
        secret,
    );
    let mut rng = ChaCha20Rng::from_entropy();
    Groth16::<OuterCurve>::prove(pk, circuit, &mut rng)
        .map_err(|e| anyhow::anyhow!("manufacturer prove failed: {:?}", e))
}

pub fn verify_manufacturer(
    vk: &OuterVerifyingKey,
    proof: &OuterProof,
    public_inputs: &[OuterFr],
) -> anyhow::Result<bool> {
    Groth16::<OuterCurve>::verify(vk, public_inputs, proof)
        .map_err(|e| anyhow::anyhow!("manufacturer verify failed: {:?}", e))
}
