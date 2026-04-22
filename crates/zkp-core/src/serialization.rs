use ark_ec::pairing::Pairing;
use ark_groth16::{Proof, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

pub fn proof_to_hex<E: Pairing>(proof: &Proof<E>) -> anyhow::Result<String> {
    let mut buf = Vec::new();
    proof.serialize_compressed(&mut buf)?;
    Ok(hex::encode(buf))
}

pub fn proof_from_hex<E: Pairing>(s: &str) -> anyhow::Result<Proof<E>> {
    let bytes = hex::decode(s.trim_start_matches("0x"))?;
    Ok(Proof::<E>::deserialize_compressed(&*bytes)?)
}

pub fn vk_to_hex<E: Pairing>(vk: &VerifyingKey<E>) -> anyhow::Result<String> {
    let mut buf = Vec::new();
    vk.serialize_compressed(&mut buf)?;
    Ok(hex::encode(buf))
}

pub fn vk_from_hex<E: Pairing>(s: &str) -> anyhow::Result<VerifyingKey<E>> {
    let bytes = hex::decode(s.trim_start_matches("0x"))?;
    Ok(VerifyingKey::<E>::deserialize_compressed(&*bytes)?)
}
