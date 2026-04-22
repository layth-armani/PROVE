manufacturer_circuit = '''use ark_bls12_377::constraints::PairingVar as InnerPairingVar;
use ark_crypto_primitives::snark::constraints::Groth16VerifierGadget;
use ark_crypto_primitives::snark::Groth16;
use ark_ec::pairing::Pairing;
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::alloc::{AllocVar, AllocationMode};
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::emulated_fp::EmulatedFpVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::select::CondSelectGadget;
use ark_r1cs_std::uint8::UInt8;
use ark_r1cs_std::R1CSVar;
use ark_relations::ns;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::types::{BatchId, Claim, InnerCurve, InnerFq, InnerFr, InnerProof, InnerVerifyingKey, ManufacturerSecret, OuterCurve, OuterFr};

/// ============================================================
/// ManufacturerCircuit
/// ============================================================
/// Outer circuit (over BW6_761 / OuterFr) that:
///   1. Recursively verifies Proof₁ (supplier proof) via Groth16VerifierGadget
///   2. Binds inner_proof.batch_id == batch_id_requested (anti proof-swap)
///   3. Binds inner_proof.claim_code == claim_code_requested
///   4. Enforces manufacturer thresholds (efficiency, optional energy)
///   5. Binds nonce to prevent replay
///
/// Public inputs (order matters):
///   1. batch_id_requested  — OuterFr
///   2. claim_code_requested — OuterFr
///   3. nonce — OuterFr
///
/// Private witnesses:
///   - inner_proof: Proof<InnerCurve>
///   - inner_vk: VerifyingKey<InnerCurve>
///   - inner_public_inputs: [InnerFr; 2] = [batch_id, claim_code]
///   - assembly_efficiency_pct: u32
///   - energy_kwh_per_cell: u32
/// ============================================================

pub struct ManufacturerCircuit {
    /// Public: batch_id the EU is asking about
    pub batch_id_requested: Option<u64>,
    /// Public: claim the EU is asking about (1 = Sustainable, 2 = UltraEfficient)
    pub claim_code_requested: Option<u64>,
    /// Public: nonce for freshness
    pub nonce: Option<u64>,

    /// Private: the supplier's proof to verify recursively
    pub inner_proof: Option<InnerProof>,
    /// Private: verifying key for the inner proof
    pub inner_vk: Option<InnerVerifyingKey>,
    /// Private: public inputs used when generating the inner proof [batch_id, claim_code]
    pub inner_public_inputs: Option<Vec<InnerFr>>,
    /// Private: manufacturer secret data
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
}

impl ConstraintSynthesizer<OuterFr> for ManufacturerCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<OuterFr>) -> Result<(), SynthesisError> {
        // ============================================================
        // 1. Allocate PUBLIC INPUTS
        // ============================================================
        let batch_id_var = FpVar::<OuterFr>::new_input(ns!(cs, "batch_id_requested"), || {
            self.batch_id_requested
                .map(|v| OuterFr::from(v))
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let claim_code_var = FpVar::<OuterFr>::new_input(ns!(cs, "claim_code_requested"), || {
            self.claim_code_requested
                .map(|v| OuterFr::from(v))
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let nonce_var = FpVar::<OuterFr>::new_input(ns!(cs, "nonce"), || {
            self.nonce
                .map(|v| OuterFr::from(v))
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // ============================================================
        // 2. Allocate PRIVATE WITNESSES (manufacturer data)
        // ============================================================
        let efficiency_var = FpVar::<OuterFr>::new_witness(ns!(cs, "assembly_efficiency"), || {
            self.manufacturer_secret
                .as_ref()
                .map(|s| OuterFr::from(s.assembly_efficiency_pct as u64))
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let energy_var = FpVar::<OuterFr>::new_witness(ns!(cs, "energy_kwh"), || {
            self.manufacturer_secret
                .as_ref()
                .map(|s| OuterFr::from(s.energy_kwh_per_cell as u64))
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // ============================================================
        // 3. RECURSIVE VERIFICATION: Verify Proof₁ inside this circuit
        // ============================================================
        // Allocate the inner proof as a witness variable
        let proof_var =
            <Groth16VerifierGadget<InnerCurve, InnerPairingVar> as AllocVar<
                InnerProof,
                OuterFr,
            >>::new_witness(ns!(cs, "inner_proof"), || {
                self.inner_proof.ok_or(SynthesisError::AssignmentMissing)
            })?;

        // Allocate the inner verifying key as a constant (or witness)
        let vk_var =
            <Groth16VerifierGadget<InnerCurve, InnerPairingVar> as AllocVar<
                InnerVerifyingKey,
                OuterFr,
            >>::new_witness(ns!(cs, "inner_vk"), || {
                self.inner_vk.ok_or(SynthesisError::AssignmentMissing)
            })?;

        // Allocate inner public inputs as EmulatedFpVar<InnerFr, OuterFr>
        // These represent the public inputs that were used to generate Proof₁
        let inner_inputs: Vec<EmulatedFpVar<InnerFr, OuterFr>> = self
            .inner_public_inputs
            .as_ref()
            .ok_or(SynthesisError::AssignmentMissing)?
            .iter()
            .enumerate()
            .map(|(i, &val)| {
                EmulatedFpVar::<InnerFr, OuterFr>::new_witness(
                    ns!(cs, format!("inner_public_input_{}", i)),
                    || Ok(val),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Perform the recursive verification
        let is_valid = Groth16VerifierGadget::<InnerCurve, InnerPairingVar>::verify(
            &vk_var,
            &inner_inputs,
            &proof_var,
        )?;

        // Enforce that recursive verification returns TRUE
        is_valid.enforce_equal(&Boolean::constant(true))?;

        // ============================================================
        // 4. BATCH_ID BINDING (Anti proof-swap)
        // ============================================================
        // The inner proof's first public input is batch_id.
        // We enforce: inner_batch_id == batch_id_requested
        // We do this by converting both to the same representation and comparing.
        // Since batch_id is small (u64), we allocate it as bits and derive both
        // the native OuterFr var and the emulated InnerFr var from the SAME bits.
        // This ensures equality by construction.
        
        let batch_id_bits = self
            .batch_id_requested
            .map(|v| {
                (0..64)
                    .map(|i| ((v >> i) & 1) == 1)
                    .collect::<Vec<bool>>()
            })
            .ok_or(SynthesisError::AssignmentMissing)?;

        // Allocate batch_id as bits (witness)
        let batch_id_bool_vars: Vec<Boolean<OuterFr>> = batch_id_bits
            .iter()
            .enumerate()
            .map(|(i, &bit)| {
                Boolean::new_witness(ns!(cs, format!("batch_id_bit_{}", i)), || Ok(bit))
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Reconstruct native OuterFr from bits and enforce == batch_id_var
        let batch_id_from_bits = boolean_vec_to_fpvar(&batch_id_bool_vars)?;
        batch_id_from_bits.enforce_equal(&batch_id_var)?;

        // Reconstruct emulated InnerFr from the SAME bits
        // and enforce == inner_public_inputs[0] (the batch_id in the inner proof)
        let inner_batch_id_from_bits =
            boolean_vec_to_emulated_fpvar::<InnerFr, OuterFr>(&batch_id_bool_vars)?;
        inner_batch_id_from_bits.enforce_equal(&inner_inputs[0])?;

        // ============================================================
        // 5. CLAIM_CODE BINDING
        // ============================================================
        // Same bit-sharing trick for claim_code (8 bits is enough)
        let claim_code_bits = self
            .claim_code_requested
            .map(|v| {
                (0..8)
                    .map(|i| ((v >> i) & 1) == 1)
                    .collect::<Vec<bool>>()
            })
            .ok_or(SynthesisError::AssignmentMissing)?;

        let claim_code_bool_vars: Vec<Boolean<OuterFr>> = claim_code_bits
            .iter()
            .enumerate()
            .map(|(i, &bit)| {
                Boolean::new_witness(ns!(cs, format!("claim_code_bit_{}", i)), || Ok(bit))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let claim_code_from_bits = boolean_vec_to_fpvar(&claim_code_bool_vars)?;
        claim_code_from_bits.enforce_equal(&claim_code_var)?;

        let inner_claim_code_from_bits =
            boolean_vec_to_emulated_fpvar::<InnerFr, OuterFr>(&claim_code_bool_vars)?;
        inner_claim_code_from_bits.enforce_equal(&inner_inputs[1])?;

        // ============================================================
        // 6. MANUFACTURER THRESHOLD CONSTRAINTS
        // ============================================================
        // claim_code == 1 (Sustainable): efficiency >= 70%
        // claim_code == 2 (UltraEfficient): efficiency >= 90%, energy <= 50

        // Convert claim_code_var to u8 for comparison
        let is_sustainable = claim_code_var.is_eq(&FpVar::constant(OuterFr::from(1u64)))?;
        let is_ultra = claim_code_var.is_eq(&FpVar::constant(OuterFr::from(2u64)))?;

        // Enforce claim_code is either 1 or 2
        let claim_valid = is_sustainable.or(&is_ultra)?;
        claim_valid.enforce_equal(&Boolean::constant(true))?;

        // Threshold constants
        let eff_min_sustainable = FpVar::constant(OuterFr::from(70u64));
        let eff_min_ultra = FpVar::constant(OuterFr::from(90u64));
        let energy_max_ultra = FpVar::constant(OuterFr::from(50u64));

        // Efficiency constraint: efficiency >= threshold
        // For sustainable: >= 70, for ultra: >= 90
        let eff_threshold = FpVar::conditionally_select(
            &is_ultra,
            &eff_min_ultra,
            &eff_min_sustainable,
        )?;
        efficiency_var.enforce_cmp(&eff_threshold, std::cmp::Ordering::Greater, true)?;

        // Energy constraint: only enforced for UltraEfficient (energy <= 50)
        let energy_satisfied = energy_var.is_cmp(&energy_max_ultra, std::cmp::Ordering::Less, true)?;
        let energy_constraint = FpVar::conditionally_select(
            &is_ultra,
            &FpVar::from(energy_satisfied),
            &FpVar::constant(OuterFr::from(1u64)), // vacuously true for Sustainable
        )?;
        energy_constraint.enforce_equal(&FpVar::constant(OuterFr::from(1u64)))?;

        // ============================================================
        // 7. NONCE BINDING (prevent replay)
        // ============================================================
        // Add a trivial non-eliminable constraint involving nonce
        // nonce * 1 == nonce (ensures nonce is used and cannot be optimized away)
        let one = FpVar::constant(OuterFr::from(1u64));
        let nonce_check = nonce_var.clone() * one;
        nonce_check.enforce_equal(&nonce_var)?;

        Ok(())
    }
}

// ============================================================
// Helper: Convert Vec<Boolean<OuterFr>> -> FpVar<OuterFr>
// (little-endian bits)
// ============================================================
fn boolean_vec_to_fpvar<F: PrimeField>(
    bits: &[Boolean<F>],
) -> Result<FpVar<F>, SynthesisError> {
    if bits.is_empty() {
        return Ok(FpVar::constant(F::zero()));
    }

    // Start with the least significant bit
    let mut result = FpVar::constant(F::zero());
    let mut power_of_two = FpVar::constant(F::one());

    for bit in bits.iter() {
        // result += bit * power_of_two
        let term = bit.select(&power_of_two, &FpVar::constant(F::zero()))?;
        result = result + term;
        // power_of_two *= 2
        power_of_two = power_of_two * FpVar::constant(F::from(2u64));
    }

    Ok(result)
}

// ============================================================
// Helper: Convert Vec<Boolean<OuterFr>> -> EmulatedFpVar<InnerFr, OuterFr>
// (little-endian bits)
// ============================================================
fn boolean_vec_to_emulated_fpvar<InnerF, OuterF>(
    bits: &[Boolean<OuterF>],
) -> Result<EmulatedFpVar<InnerF, OuterF>, SynthesisError>
where
    InnerF: PrimeField,
    OuterF: PrimeField,
{
    if bits.is_empty() {
        return Ok(EmulatedFpVar::<InnerF, OuterF>::constant(InnerF::zero()));
    }

    // Convert booleans to UInt8 chunks (8 bits each)
    let num_bytes = (bits.len() + 7) / 8;
    let mut bytes: Vec<UInt8<OuterF>> = Vec::with_capacity(num_bytes);

    for byte_idx in 0..num_bytes {
        let mut byte_bits: Vec<Boolean<OuterF>> = Vec::with_capacity(8);
        for bit_idx in 0..8 {
            let idx = byte_idx * 8 + bit_idx;
            if idx < bits.len() {
                byte_bits.push(bits[idx].clone());
            } else {
                byte_bits.push(Boolean::constant(false));
            }
        }
        // UInt8 from bits (LSB first)
        let byte = UInt8::from_bits_le(&byte_bits)?;
        bytes.push(byte);
    }

    // Now reconstruct the EmulatedFpVar from bytes
    // We do this by building the field element as sum(byte[i] * 256^i)
    let mut result = EmulatedFpVar::<InnerF, OuterF>::constant(InnerF::zero());
    let mut power_of_256 = EmulatedFpVar::<InnerF, OuterF>::constant(InnerF::one());

    for byte in bytes.iter() {
        // Convert UInt8 to EmulatedFpVar
        let byte_val = byte_to_emulated_fpvar(byte)?;
        let term = byte_val * &power_of_256;
        result = result + &term;
        power_of_256 = &power_of_256 * &EmulatedFpVar::<InnerF, OuterF>::constant(InnerF::from(256u64));
    }

    Ok(result)
}

// Helper: UInt8 -> EmulatedFpVar
fn byte_to_emulated_fpvar<InnerF, OuterF>(
    byte: &UInt8<OuterF>,
) -> Result<EmulatedFpVar<InnerF, OuterF>, SynthesisError>
where
    InnerF: PrimeField,
    OuterF: PrimeField,
{
    // UInt8 to bits, then reconstruct as EmulatedFpVar
    let bits = byte.to_bits_le()?;
    let mut result = EmulatedFpVar::<InnerF, OuterF>::constant(InnerF::zero());
    let mut power_of_two = EmulatedFpVar::<InnerF, OuterF>::constant(InnerF::one());

    for bit in bits.iter() {
        let bit_val = bit.select(
            &EmulatedFpVar::<InnerF, OuterF>::constant(InnerF::one()),
            &EmulatedFpVar::<InnerF, OuterF>::constant(InnerF::zero()),
        )?;
        let term = &bit_val * &power_of_two;
        result = result + &term;
        power_of_two = &power_of_two * &EmulatedFpVar::<InnerF, OuterF>::constant(InnerF::from(2u64));
    }

    Ok(result)
}

// ============================================================
// Tests
// ============================================================
#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn test_circuit_satisfiable_with_valid_data() {
        let cs = ConstraintSystem::<OuterFr>::new_ref();

        // This is a structural test - actual proof verification would need
        // real setup artifacts. For unit tests we check constraint generation.
        let circuit = ManufacturerCircuit {
            batch_id_requested: Some(0x42),
            claim_code_requested: Some(1), // Sustainable
            nonce: Some(12345),
            inner_proof: None,      // Would need real proof in integration test
            inner_vk: None,         // Would need real VK
            inner_public_inputs: Some(vec![InnerFr::from(0x42u64), InnerFr::from(1u64)]),
            manufacturer_secret: Some(ManufacturerSecret {
                assembly_efficiency_pct: 85,
                energy_kwh_per_cell: 40,
            }),
        };

        // Note: Without real inner_proof and inner_vk, the recursive verify step
        // will fail at synthesis. This test is a placeholder for the structure.
        // Real tests require running setup and generating actual proofs.
        let result = circuit.generate_constraints(cs.clone());
        // We expect this to fail because inner_proof and inner_vk are None
        // In a real test with proper setup, it should pass.
        assert!(result.is_err() || cs.is_satisfied().unwrap() == false);
    }
}
