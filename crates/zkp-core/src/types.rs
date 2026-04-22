use ark_bls12_377::Bls12_377;
use ark_bw6_761::BW6_761;
use ark_groth16::{Proof, ProvingKey, VerifyingKey};
use serde::{Deserialize, Serialize};

/// =======================
/// Curve Type Definitions
/// =======================

/// Inner curve used for base proofs (e.g. supplier proofs)
pub type InnerCurve = Bls12_377;

/// Scalar field for the inner curve (used for private/public inputs)
pub type InnerFr = ark_bls12_377::Fr;

/// Base field for the inner curve
pub type InnerFq = ark_bls12_377::Fq;

/// Outer curve used for recursive proofs (e.g. manufacturer proofs verifying supplier proofs)
pub type OuterCurve = BW6_761;

/// Scalar field for the outer curve
pub type OuterFr = ark_bw6_761::Fr;


/// =======================
/// Proof Type Aliases
/// =======================

/// Proof generated on the inner curve (supplier-level proof)
pub type InnerProof = Proof<InnerCurve>;

/// Proof generated on the outer curve (manufacturer-level proof, possibly recursive)
pub type OuterProof = Proof<OuterCurve>;

/// Proving key for inner proofs
pub type InnerProvingKey = ProvingKey<InnerCurve>;

/// Verifying key for inner proofs
pub type InnerVerifyingKey = VerifyingKey<InnerCurve>;

/// Proving key for outer proofs
pub type OuterProvingKey = ProvingKey<OuterCurve>;

/// Verifying key for outer proofs
pub type OuterVerifyingKey = VerifyingKey<OuterCurve>;


/// =======================
/// Batch Identifier
/// =======================

/// Unique identifier for a batch of lithium (or any tracked product)
/// This is used as a public input in ZK proofs to link all actors to the same batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BatchId(pub u64);

/// Helper methods for BatchId
impl BatchId {
    /// Create a BatchId from a hexadecimal string (e.g. "0x1a2b")
    pub fn from_hex(s: &str) -> anyhow::Result<Self> {
        let s = s.trim_start_matches("0x");
        Ok(Self(u64::from_str_radix(s, 16)?))
    }

    /// Convert the BatchId to a hexadecimal string
    pub fn to_hex(&self) -> String {
        format!("0x{:x}", self.0)
    }
}

/// Display implementation for pretty-printing BatchId
impl std::fmt::Display for BatchId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:x}", self.0)
    }
}


/// =======================
/// Claims (Public Statements)
/// =======================

/// Enum representing the type of claim being proven.
/// These are public statements verified via ZKP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Claim {
    /// Basic sustainability claim
    Sustainable,

    /// Stronger efficiency + sustainability claim
    UltraEfficient,
}

/// Hardcoded parameters for each claim (used in circuits)
impl Claim {
    /// Convert claim to a numeric code (useful for circuit inputs)
    pub fn to_code(&self) -> u64 {
        match self {
            Claim::Sustainable => 1,
            Claim::UltraEfficient => 2,
        }
    }

    /// Maximum allowed water usage (liters per kg)
    pub fn water_max(&self) -> u32 {
        match self {
            Claim::Sustainable => 2000,
            Claim::UltraEfficient => 800,
        }
    }

    /// Minimum required recycled material percentage
    pub fn recycled_min(&self) -> u32 {
        match self {
            Claim::Sustainable => 10,
            Claim::UltraEfficient => 30,
        }
    }

    /// Minimum required efficiency percentage (manufacturer-side)
    pub fn efficiency_min(&self) -> u32 {
        match self {
            Claim::Sustainable => 70,
            Claim::UltraEfficient => 90,
        }
    }

    /// Maximum allowed energy consumption (optional constraint)
    pub fn energy_max(&self) -> Option<u32> {
        match self {
            Claim::Sustainable => None,
            Claim::UltraEfficient => Some(50),
        }
    }
}


/// =======================
/// Private Inputs (Secrets)
/// =======================

/// Supplier private data (never revealed, only used inside ZKP)
#[derive(Debug, Clone)]
pub struct SupplierSecret {
    /// Water usage per kg of lithium
    pub water_liters_per_kg: u32,

    /// Percentage of recycled material used
    pub recycled_content_pct: u32,
}

/// Manufacturer private data (also hidden inside ZKP)
#[derive(Debug, Clone)]
pub struct ManufacturerSecret {
    /// Assembly efficiency percentage
    pub assembly_efficiency_pct: u32,

    /// Energy consumption per battery cell
    pub energy_kwh_per_cell: u32,
}