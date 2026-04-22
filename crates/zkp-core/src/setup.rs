use std::path::Path;

use ark_groth16::Groth16;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use crate::{
    supplier_circuit::SupplierCircuit,
    types::{Claim, InnerCurve, InnerProvingKey, InnerVerifyingKey},
};

/// Keys produced by the trusted setup for the inner (supplier) circuit.
pub struct SetupArtifacts {
    pub inner_pk: InnerProvingKey,
    pub inner_vk: InnerVerifyingKey,
}

/// Load keys from disk if they exist, otherwise run setup and save them.
pub fn load_or_generate(keys_dir: &Path) -> anyhow::Result<SetupArtifacts> {
    let pk_path = keys_dir.join("inner_pk.bin");
    let vk_path = keys_dir.join("inner_vk.bin");

    if pk_path.exists() && vk_path.exists() {
        tracing::info!("Loading existing keys from disk...");
        let inner_pk = load_key(&pk_path)?;
        let inner_vk = load_key(&vk_path)?;
        tracing::info!("Keys loaded.");
        return Ok(SetupArtifacts { inner_pk, inner_vk });
    }

    tracing::info!("No keys found — running trusted setup (this may take a moment)...");
    std::fs::create_dir_all(keys_dir)?;

    let mut rng = ChaCha20Rng::from_entropy();

    let circuit = SupplierCircuit::blank(Claim::Sustainable);
    let (inner_pk, inner_vk) = Groth16::<InnerCurve>::circuit_specific_setup(circuit, &mut rng)
        .map_err(|e| anyhow::anyhow!("Setup failed: {:?}", e))?;

    save_key(&inner_pk, &pk_path)?;
    save_key(&inner_vk, &vk_path)?;
    tracing::info!("Setup complete. Keys saved to {:?}", keys_dir);

    Ok(SetupArtifacts { inner_pk, inner_vk })
}

fn save_key<T: CanonicalSerialize>(key: &T, path: &Path) -> anyhow::Result<()> {
    let mut buf = Vec::new();
    key.serialize_compressed(&mut buf)?;
    std::fs::write(path, buf)?;
    Ok(())
}

fn load_key<T: CanonicalDeserialize>(path: &Path) -> anyhow::Result<T> {
    let buf = std::fs::read(path)?;
    Ok(T::deserialize_compressed(&*buf)?)
}
