use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use zkp_core::{
    load_or_generate, proof_from_hex, proof_to_hex, prove::supplier_public_inputs,
    prove_manufacturer, BatchId, Claim, InnerProof, ManufacturerSecret,
    SetupArtifacts,
};

#[derive(Clone)]
struct StoredProof1 {
    proof: InnerProof,
    claim: Claim,
}

#[derive(Clone)]
struct AppState {
    setup: Arc<SetupArtifacts>,
    proofs: Arc<RwLock<HashMap<u64, StoredProof1>>>,
    mfg_data: Arc<HashMap<u64, ManufacturerSecret>>,
}

#[derive(Deserialize)]
struct IngestRequest {
    batch_id: String,
    proof: String,
    #[allow(dead_code)]
    claim: String,
}

#[derive(Deserialize)]
struct VerifyRequest {
    batch_id: String,
    claim: String,
    nonce: u64,
    #[serde(default)]
    force_swap: bool,
    #[serde(default)]
    force_forge: bool,
}

#[derive(Serialize)]
struct VerifyPublicInputs {
    batch_id: String,
    claim: String,
    nonce: u64,
}

#[derive(Serialize)]
struct VerifyResponse {
    proof2: String,
    public_inputs: VerifyPublicInputs,
}

/// Manufacturer's own (secret) data per batch.
fn seed_manufacturer_data() -> HashMap<u64, ManufacturerSecret> {
    let mut m = HashMap::new();
    // 0x42 → passes threshold
    m.insert(0x42, ManufacturerSecret { assembly_efficiency_pct: 85, energy_kwh_per_cell: 40 });
    // 0xAB → passes threshold (used for proof-swap)
    m.insert(0xAB, ManufacturerSecret { assembly_efficiency_pct: 80, energy_kwh_per_cell: 45 });
    // 0xCD → fails threshold (efficiency below 70)
    m.insert(0xCD, ManufacturerSecret { assembly_efficiency_pct: 60, energy_kwh_per_cell: 55 });
    m
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,manufacturer_service=info,zkp_core=info".into()),
        )
        .init();

    tracing::info!("Manufacturer service starting...");

    let keys_dir = PathBuf::from("data/keys");
    let setup = Arc::new(load_or_generate(&keys_dir)?);

    let state = AppState {
        setup,
        proofs: Arc::new(RwLock::new(HashMap::new())),
        mfg_data: Arc::new(seed_manufacturer_data()),
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/ingest", post(ingest))
        .route("/verify", post(verify))
        .with_state(state);

    let addr: SocketAddr = "0.0.0.0:3002".parse()?;
    tracing::info!("Manufacturer service listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn ingest(
    State(state): State<AppState>,
    Json(req): Json<IngestRequest>,
) -> impl IntoResponse {
    let bid = match BatchId::from_hex(&req.batch_id) {
        Ok(b) => b,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };

    let proof: InnerProof = match proof_from_hex(&req.proof) {
        Ok(p) => p,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("bad proof: {}", e)).into_response(),
    };

    state.proofs.write().await.insert(
        bid.0,
        StoredProof1 { proof, claim: Claim::Sustainable },
    );
    tracing::info!("📥 Ingested Proof₁ for batch {}", bid);
    StatusCode::OK.into_response()
}

async fn verify(
    State(state): State<AppState>,
    Json(req): Json<VerifyRequest>,
) -> impl IntoResponse {
    let bid = match BatchId::from_hex(&req.batch_id) {
        Ok(b) => b,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };

    let claim = match req.claim.as_str() {
        "sustainable" => Claim::Sustainable,
        other => {
            return (StatusCode::BAD_REQUEST, format!("unknown claim '{}'", other)).into_response()
        }
    };

    // Choose which stored Proof₁ to use. In --force-swap the manufacturer
    // cheats: picks Proof₁ from a DIFFERENT batch. The circuit binding will
    // then make Proof₂ generation unsatisfiable.
    let proofs = state.proofs.read().await;
    let (inner_batch_id, stored) = if req.force_swap {
        match proofs.iter().find(|(&k, _)| k != bid.0) {
            Some((k, v)) => (*k, v.clone()),
            None => {
                return (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "no other proof available to swap".to_string(),
                )
                    .into_response();
            }
        }
    } else {
        match proofs.get(&bid.0) {
            Some(v) => (bid.0, v.clone()),
            None => {
                return (
                    StatusCode::NOT_FOUND,
                    format!("no Proof₁ on file for batch {}", bid),
                )
                    .into_response();
            }
        }
    };
    drop(proofs);

    let mfg = match state.mfg_data.get(&bid.0) {
        Some(s) => s.clone(),
        None => {
            return (
                StatusCode::NOT_FOUND,
                format!("no manufacturer data for batch {}", bid),
            )
                .into_response();
        }
    };

    // When swapping, the inner proof's public inputs are those of the *other*
    // batch — so pass the matching public inputs to the prover. The outer
    // circuit will still fail because its `batch_id_requested` (= bid) does
    // not match the bits that reconstruct the inner public inputs.
    let inner_pub = supplier_public_inputs(BatchId(inner_batch_id), stored.claim);

    let proof2 = match prove_manufacturer(
        bid,
        claim,
        req.nonce,
        stored.proof,
        state.setup.inner_vk.clone(),
        inner_pub,
        mfg,
    ) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!("Proof₂ generation failed for {}: {}", bid, e);
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("proof generation failed: {}", e),
            )
                .into_response();
        }
    };

    let mut proof_hex = match proof_to_hex(&proof2) {
        Ok(h) => h,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    if req.force_forge {
        // Replace first two hex chars with invalid hex so hex::decode fails at the verifier.
        if proof_hex.len() >= 2 {
            proof_hex.replace_range(0..2, "zz");
        }
        tracing::info!("🧪 Forgery injected for batch {}", bid);
    }

    Json(VerifyResponse {
        proof2: proof_hex,
        public_inputs: VerifyPublicInputs {
            batch_id: bid.to_hex(),
            claim: "sustainable".to_string(),
            nonce: req.nonce,
        },
    })
    .into_response()
}
