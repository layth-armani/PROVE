use ark_bls12_377::Bls12_377;
use ark_bw6_761::BW6_761;
use ark_groth16::{Proof, ProvingKey, VerifyingKey};
use serde::{Deserialize, Serialize};

// Curve type aliases
pub type InnerCurve = Bls12_377;
pub type InnerFr = ark_bls12_377::Fr;
pub type InnerFq = ark_bls12_377::Fq;
pub type OuterCurve = BW6_761;
pub type OuterFr = ark_bw6_761::Fr;

// Proof type aliases
pub type InnerProof = Proof<InnerCurve>;
pub type OuterProof = Proof<OuterCurve>;
pub type InnerProvingKey = ProvingKey<InnerCurve>;
pub type InnerVerifyingKey = VerifyingKey<InnerCurve>;
pub type OuterProvingKey = ProvingKey<OuterCurve>;
pub type OuterVerifyingKey = VerifyingKey<OuterCurve>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BatchId(pub u64);

impl BatchId {
    pub fn from_hex(s: &str) -> anyhow::Result<Self> {
        let s = s.trim_start_matches("0x");
        Ok(Self(u64::from_str_radix(s, 16)?))
    }

    pub fn to_hex(&self) -> String {
        format!("0x{:x}", self.0)
    }
}

impl std::fmt::Display for BatchId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:x}", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Claim {
    Sustainable,
    UltraEfficient,
}

impl Claim {
    pub fn to_code(&self) -> u64 {
        match self {
            Claim::Sustainable => 1,
            Claim::UltraEfficient => 2,
        }
    }

    pub fn water_max(&self) -> u32 {
        match self {
            Claim::Sustainable => 2000,
            Claim::UltraEfficient => 800,
        }
    }

    pub fn recycled_min(&self) -> u32 {
        match self {
            Claim::Sustainable => 10,
            Claim::UltraEfficient => 30,
        }
    }

    pub fn efficiency_min(&self) -> u32 {
        match self {
            Claim::Sustainable => 70,
            Claim::UltraEfficient => 90,
        }
    }

    pub fn energy_max(&self) -> Option<u32> {
        match self {
            Claim::Sustainable => None,
            Claim::UltraEfficient => Some(50),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SupplierSecret {
    pub water_liters_per_kg: u32,
    pub recycled_content_pct: u32,
}

#[derive(Debug, Clone)]
pub struct ManufacturerSecret {
    pub assembly_efficiency_pct: u32,
    pub energy_kwh_per_cell: u32,
}
