use ark_ff::Field;
use ark_r1cs_std::{
    alloc::AllocVar,
    fields::fp::FpVar,
    prelude::{Boolean, EqGadget, FieldVar},
    R1CSVar,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::types::{Claim, InnerFr};

pub struct ManufacturerCircuit {
    // Public inputs
    pub batch_id: u64,
    pub claim: Claim,
    pub innerProof: InnerProof,

    // Private witnesses (None during key generation with a dummy circuit)
    pub assembly_efficiency_pct: u32,
    pub energy_kwh_per_cell: u32,
}

impl ManufacturerCircuit {
    pub fn new(
        batch_id: u64,
        claim: Claim,
        assembly_efficiency_pct: u32,
        energy_kwh_per_cell: u32,
    ) -> Self {
        Self {
            batch_id,
            claim,
            assembly_efficiency_pct: Some(assembly_efficiency_pct),
            energy_kwh_per_cell: Some(energy_kwh_per_cell),
        }
    }
}