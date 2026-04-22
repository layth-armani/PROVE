use ark_bls12_377::constraints::PairingVar as InnerPairingVar;
use ark_crypto_primitives::snark::constraints::{BooleanInputVar, SNARKGadget};
use ark_ff::PrimeField;
use ark_groth16::constraints::{Groth16VerifierGadget, ProofVar, VerifyingKeyVar};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::convert::ToBitsGadget;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::One;

use crate::types::{
    BatchId, Claim, InnerCurve, InnerFr, InnerProof, InnerVerifyingKey,
    ManufacturerSecret, OuterFr,
};

/// Outer circuit (BW6-761 / OuterFr) that:
///   1. Recursively verifies Proof₁ (supplier proof) via Groth16VerifierGadget
///   2. Binds inner_proof.batch_id == batch_id_requested (anti proof-swap)
///   3. Binds inner_proof.claim_code == claim_code_requested
///   4. Enforces manufacturer threshold (efficiency ≥ 70 for Sustainable)
///   5. Binds nonce so it cannot be optimized away
///
/// Public inputs (order matters):
///   1. batch_id_requested
///   2. claim_code_requested
///   3. nonce
#[derive(Clone)]
pub struct ManufacturerCircuit {
    pub batch_id_requested: Option<u64>,
    pub claim_code_requested: Option<u64>,
    pub nonce: Option<u64>,

    pub inner_proof: Option<InnerProof>,
    pub inner_vk: Option<InnerVerifyingKey>,
    /// [batch_id, claim_code] in InnerFr. Informational only — the actual
    /// binding inside the circuit comes from bit-sharing with the outer inputs.
    pub inner_public_inputs: Option<Vec<InnerFr>>,
    pub manufacturer_secret: Option<ManufacturerSecret>,
}

impl ManufacturerCircuit {
    pub fn new(
        batch_id: BatchId,
        claim: Claim,
        nonce: u64,
        inner_proof: InnerProof,
        inner_vk: InnerVerifyingKey,
        inner_public_inputs: Vec<InnerFr>,
        secret: ManufacturerSecret,
    ) -> Self {
        Self {
            batch_id_requested: Some(batch_id.0),
            claim_code_requested: Some(claim.to_code()),
            nonce: Some(nonce),
            inner_proof: Some(inner_proof),
            inner_vk: Some(inner_vk),
            inner_public_inputs: Some(inner_public_inputs),
            manufacturer_secret: Some(secret),
        }
    }

    /// Dummy circuit for Groth16 setup. All witnesses are `None`; `new_witness`
    /// closures return `AssignmentMissing`, which `circuit_specific_setup`
    /// accepts (setup only needs the R1CS shape).
    pub fn blank() -> Self {
        Self {
            batch_id_requested: None,
            claim_code_requested: None,
            nonce: None,
            inner_proof: None,
            inner_vk: None,
            inner_public_inputs: None,
            manufacturer_secret: None,
        }
    }
}

impl ConstraintSynthesizer<OuterFr> for ManufacturerCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<OuterFr>) -> Result<(), SynthesisError> {
        // ── 1. Public inputs ────────────────────────────────────────────────
        let batch_id_var = FpVar::<OuterFr>::new_input(cs.clone(), || {
            self.batch_id_requested
                .map(OuterFr::from)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let claim_code_var = FpVar::<OuterFr>::new_input(cs.clone(), || {
            self.claim_code_requested
                .map(OuterFr::from)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let nonce_var = FpVar::<OuterFr>::new_input(cs.clone(), || {
            self.nonce
                .map(OuterFr::from)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // ── 2. Manufacturer private data ───────────────────────────────────
        let efficiency_var = FpVar::<OuterFr>::new_witness(cs.clone(), || {
            self.manufacturer_secret
                .as_ref()
                .map(|s| OuterFr::from(s.assembly_efficiency_pct as u64))
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Kept as a witness so the circuit shape is stable if an energy
        // threshold is added later; currently unconstrained for Sustainable.
        let _energy_var = FpVar::<OuterFr>::new_witness(cs.clone(), || {
            self.manufacturer_secret
                .as_ref()
                .map(|s| OuterFr::from(s.energy_kwh_per_cell as u64))
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // ── 3. Inner proof / VK / public inputs ────────────────────────────
        let proof_var = ProofVar::<InnerCurve, InnerPairingVar>::new_witness(cs.clone(), || {
            self.inner_proof.clone().ok_or(SynthesisError::AssignmentMissing)
        })?;

        let vk_var = VerifyingKeyVar::<InnerCurve, InnerPairingVar>::new_witness(cs.clone(), || {
            self.inner_vk.clone().ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Build the inner public inputs as bit-vectors over OuterFr. The same
        // bits are used to reconstruct the outer public inputs → the inner
        // proof's public inputs are bound to the outer ones by construction.
        let inner_fr_bits = InnerFr::MODULUS_BIT_SIZE as usize;

        let batch_id_bits = allocate_low_bits::<OuterFr>(
            cs.clone(),
            self.batch_id_requested,
            64,
        )?;
        // Reconstruct OuterFr from those bits and enforce == batch_id_var.
        bits_to_fpvar::<OuterFr>(&batch_id_bits)?
            .enforce_equal(&batch_id_var)?;

        let claim_code_bits = allocate_low_bits::<OuterFr>(
            cs.clone(),
            self.claim_code_requested,
            8,
        )?;
        bits_to_fpvar::<OuterFr>(&claim_code_bits)?
            .enforce_equal(&claim_code_var)?;

        // Claim code must be 1 (Sustainable) — the only claim we support.
        claim_code_var.enforce_equal(&FpVar::constant(OuterFr::from(
            Claim::Sustainable.to_code(),
        )))?;

        // Pad to InnerFr::MODULUS_BIT_SIZE with constant false to form a full
        // scalar-field representation for BooleanInputVar.
        let batch_id_input_bits = pad_with_false(&batch_id_bits, inner_fr_bits);
        let claim_code_input_bits = pad_with_false(&claim_code_bits, inner_fr_bits);

        let input_var: BooleanInputVar<InnerFr, OuterFr> =
            BooleanInputVar::new(vec![batch_id_input_bits, claim_code_input_bits]);

        // Recursive verification: enforces the inner Groth16 proof is valid
        // *for these exact public inputs* (the ones bound above).
        let is_valid =
            <Groth16VerifierGadget<InnerCurve, InnerPairingVar> as SNARKGadget<
                InnerFr,
                OuterFr,
                ark_groth16::Groth16<InnerCurve>,
            >>::verify(&vk_var, &input_var, &proof_var)?;
        is_valid.enforce_equal(&Boolean::constant(true))?;

        // ── 4. Manufacturer threshold: efficiency ≥ 70 ────────────────────
        // Enforce (efficiency − 70) fits in 32 bits → non-negative and small.
        let eff_min = FpVar::<OuterFr>::constant(OuterFr::from(
            Claim::Sustainable.efficiency_min() as u64,
        ));
        let eff_diff = &efficiency_var - &eff_min;
        enforce_range_bits(&eff_diff, 32)?;

        // ── 5. Nonce binding ──────────────────────────────────────────────
        // Force nonce into the R1CS: (nonce * 1) == nonce.
        let one = FpVar::<OuterFr>::constant(OuterFr::one());
        (&nonce_var * &one).enforce_equal(&nonce_var)?;

        Ok(())
    }
}

/// Allocate `bit_len` witness bits encoding `value` in little-endian order.
/// During setup `value` is `None` and each allocation returns
/// `AssignmentMissing`, which `new_witness` accepts.
fn allocate_low_bits<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    value: Option<u64>,
    bit_len: usize,
) -> Result<Vec<Boolean<F>>, SynthesisError> {
    (0..bit_len)
        .map(|i| {
            Boolean::new_witness(cs.clone(), || {
                let v = value.ok_or(SynthesisError::AssignmentMissing)?;
                Ok(((v >> i) & 1) == 1)
            })
        })
        .collect()
}

fn pad_with_false<F: PrimeField>(bits: &[Boolean<F>], to_len: usize) -> Vec<Boolean<F>> {
    let mut out: Vec<Boolean<F>> = bits.to_vec();
    while out.len() < to_len {
        out.push(Boolean::constant(false));
    }
    out
}

/// Enforce `val ∈ [0, 2^bit_len)` by bit decomposition.
fn enforce_range_bits(val: &FpVar<OuterFr>, bit_len: usize) -> Result<(), SynthesisError> {
    let bits = val.to_bits_le()?;
    for bit in bits.iter().skip(bit_len) {
        bit.enforce_equal(&Boolean::FALSE)?;
    }
    Ok(())
}

/// Reconstruct `FpVar<F>` from little-endian bits.
fn bits_to_fpvar<F: PrimeField>(bits: &[Boolean<F>]) -> Result<FpVar<F>, SynthesisError> {
    let mut acc = FpVar::<F>::zero();
    let mut pow = F::one();
    let two = F::from(2u64);
    for bit in bits {
        let term = FpVar::<F>::from(bit.clone()) * FpVar::constant(pow);
        acc = acc + term;
        pow *= two;
    }
    Ok(acc)
}
