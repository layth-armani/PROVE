use ark_r1cs_std::{
    alloc::AllocVar,
    convert::ToBitsGadget,
    fields::fp::FpVar,
    prelude::{Boolean, EqGadget},
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::types::{Claim, InnerFr};

/// The supplier's ZK circuit — proves that a lithium batch meets sustainability
/// thresholds without revealing the underlying measurements.
///
/// Public inputs (in order, as required by the verifying key):
///   1. batch_id   — u64 encoded as InnerFr
///   2. claim_code — 1 = Sustainable
///
/// Private witnesses:
///   - water_liters_per_kg
///   - recycled_content_pct
#[derive(Clone)]
pub struct SupplierCircuit {
    // Public inputs
    pub batch_id: u64,
    pub claim: Claim,

    // Private witnesses (None during key generation with a dummy circuit)
    pub water_liters_per_kg: Option<u32>,
    pub recycled_content_pct: Option<u32>,
}

impl SupplierCircuit {
    pub fn new(
        batch_id: u64,
        claim: Claim,
        water_liters_per_kg: u32,
        recycled_content_pct: u32,
    ) -> Self {
        Self {
            batch_id,
            claim,
            water_liters_per_kg: Some(water_liters_per_kg),
            recycled_content_pct: Some(recycled_content_pct),
        }
    }

    /// Dummy instance used only during trusted setup — witnesses are zeroed.
    pub fn blank(claim: Claim) -> Self {
        Self {
            batch_id: 0,
            claim,
            water_liters_per_kg: None,
            recycled_content_pct: None,
        }
    }
}

impl ConstraintSynthesizer<InnerFr> for SupplierCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<InnerFr>,
    ) -> Result<(), SynthesisError> {
        // ── Public inputs ────────────────────────────────────────────────────
        let batch_id_var = FpVar::<InnerFr>::new_input(cs.clone(), || {
            Ok(InnerFr::from(self.batch_id))
        })?;

        let claim_code_var = FpVar::<InnerFr>::new_input(cs.clone(), || {
            Ok(InnerFr::from(self.claim.to_code()))
        })?;

        // Bind the public inputs into constraints so the proof is actually
        // tied to them (not just "declared" as inputs).
        //
        // batch_id is specified as a u64 in the API, so enforce it fits in 64 bits.
        enforce_non_negative(cs.clone(), &batch_id_var, 64)?;

        // claim_code is currently fixed to Sustainable (1).
        let sustainable_code =
            FpVar::<InnerFr>::new_constant(cs.clone(), InnerFr::from(1u64))?;
        claim_code_var.enforce_equal(&sustainable_code)?;

        // ── Private witnesses ────────────────────────────────────────────────
        let water_var = FpVar::<InnerFr>::new_witness(cs.clone(), || {
            Ok(InnerFr::from(
                self.water_liters_per_kg.unwrap_or(0) as u64,
            ))
        })?;

        let recycled_var = FpVar::<InnerFr>::new_witness(cs.clone(), || {
            Ok(InnerFr::from(
                self.recycled_content_pct.unwrap_or(0) as u64,
            ))
        })?;

        // ── Threshold constants ──────────────────────────────────────────────
        let water_max = FpVar::<InnerFr>::new_constant(
            cs.clone(),
            InnerFr::from(self.claim.water_max() as u64),
        )?;

        let recycled_min = FpVar::<InnerFr>::new_constant(
            cs.clone(),
            InnerFr::from(self.claim.recycled_min() as u64),
        )?;

        // ── Constraints ──────────────────────────────────────────────────────

        // water <= water_max  →  (water_max - water) must fit in 32 bits
        let water_diff = water_max - &water_var;
        enforce_non_negative(cs.clone(), &water_diff, 32)?;

        // recycled >= recycled_min  →  (recycled - recycled_min) must fit in 32 bits
        let recycled_diff = &recycled_var - recycled_min;
        enforce_non_negative(cs.clone(), &recycled_diff, 32)?;

        Ok(())
    }
}

/// Enforces that `val` is non-negative by decomposing it into `bit_len` bits.
/// In a prime field "non-negative" means the value fits in [0, 2^bit_len).
/// If val were negative (a large field element near the prime), the high bits
/// would be set and the constraint would be unsatisfiable.
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
