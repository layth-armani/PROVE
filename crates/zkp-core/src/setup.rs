use std::path::Path;

use ark_groth16::Groth16;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use crate::{
    supplier_circuit::SupplierCircuit,
    types::{
        Claim, InnerCurve, InnerProvingKey, InnerVerifyingKey,
    },
};

pub struct SetupArtifacts {
    pub inner_pk: InnerProvingKey,
    pub inner_vk: InnerVerifyingKey,
}

pub fn load_or_generate(keys_dir: &Path) -> anyhow::Result<SetupArtifacts> {
    let inner_pk_path = keys_dir.join("inner_pk.bin");
    let inner_vk_path = keys_dir.join("inner_vk.bin");

    if inner_pk_path.exists() && inner_vk_path.exists() {
        tracing::info!("Loading existing keys (inner) from disk...");
        let inner_pk = load_key(&inner_pk_path)?;
        let inner_vk = load_key(&inner_vk_path)?;
        tracing::info!("All keys loaded.");
        return Ok(SetupArtifacts { inner_pk, inner_vk });
    }

    tracing::info!("No keys found — running trusted setup for inner circuit...");
    std::fs::create_dir_all(keys_dir)?;

    let mut rng = ChaCha20Rng::from_entropy();

    // Inner circuit setup (SupplierCircuit over BLS12-377)
    tracing::info!("Running inner circuit setup...");
    let inner_circuit = SupplierCircuit::blank(Claim::Sustainable);
    let (inner_pk, inner_vk) = Groth16::<InnerCurve>::circuit_specific_setup(inner_circuit, &mut rng)
        .map_err(|e| anyhow::anyhow!("Inner setup failed: {:?}", e))?;

    save_key(&inner_pk, &inner_pk_path)?;
    save_key(&inner_vk, &inner_vk_path)?;
    tracing::info!("Inner setup complete.");

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
