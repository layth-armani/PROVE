use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use zkp_core::{
    load_or_generate, proof_to_hex, prove_supplier, vk_to_hex, BatchId, Claim, InnerProof,
    SetupArtifacts, SupplierSecret,
};

#[derive(Clone)]
struct AppState {
    setup: Arc<SetupArtifacts>,
    /// batch_id → (InnerProof, claim) for batches we successfully proved.
    proofs: Arc<HashMap<u64, (InnerProof, Claim)>>,
}

#[derive(Deserialize)]
struct Proof1Request {
    batch_id: String,
}

#[derive(Serialize)]
struct Proof1PublicInputs {
    batch_id: String,
    claim: &'static str,
}

#[derive(Serialize)]
struct Proof1Response {
    proof: String,
    public_inputs: Proof1PublicInputs,
}

#[derive(Serialize)]
struct VkResponse {
    vk: String,
}

#[derive(Serialize)]
struct IngestRequest {
    batch_id: String,
    proof: String,
    claim: &'static str,
}

fn seed_batches() -> Vec<(u64, SupplierSecret)> {
    vec![
        // 0x42: clean — passes sustainable threshold
        (0x42, SupplierSecret { water_liters_per_kg: 500, recycled_content_pct: 50 }),
        // 0x99: dirty — fails (water too high, recycled too low)
        (0x99, SupplierSecret { water_liters_per_kg: 3000, recycled_content_pct: 5 }),
        // 0xAB: clean — passes (used for proof-swap demo)
        (0xAB, SupplierSecret { water_liters_per_kg: 800, recycled_content_pct: 30 }),
        // 0xCD: clean supplier; manufacturer's own data will fail for this batch
        (0xCD, SupplierSecret { water_liters_per_kg: 700, recycled_content_pct: 40 }),
    ]
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,supplier_service=info,zkp_core=info".into()),
        )
        .init();

    tracing::info!("Supplier service starting...");

    let keys_dir = PathBuf::from("data/keys");
    let setup = Arc::new(load_or_generate(&keys_dir)?);

    tracing::info!("Generating pre-seeded supplier proofs...");
    let mut proofs: HashMap<u64, (InnerProof, Claim)> = HashMap::new();
    for (batch_id, secret) in seed_batches() {
        let bid = BatchId(batch_id);
        let claim = Claim::Sustainable;
        if secret.water_liters_per_kg > claim.water_max() {
            tracing::warn!(
                "  ✗ Batch {} rejected: water {} > max {}",
                bid, secret.water_liters_per_kg, claim.water_max()
            );
            continue;
        }
        if secret.recycled_content_pct < claim.recycled_min() {
            tracing::warn!(
                "  ✗ Batch {} rejected: recycled {}% < min {}%",
                bid, secret.recycled_content_pct, claim.recycled_min()
            );
            continue;
        }
        match prove_supplier(&setup.inner_pk, bid, claim, secret) {
            Ok(proof) => {
                tracing::info!("  ✔ Proof₁ generated for batch {}", bid);
                proofs.insert(batch_id, (proof, claim));
            }
            Err(e) => {
                tracing::warn!("  ✗ Could not generate Proof₁ for batch {}: {}", bid, e);
            }
        }
    }
    let proofs = Arc::new(proofs);

    // Ship valid proofs to the manufacturer (best-effort, with retry).
    let proofs_clone = proofs.clone();
    tokio::spawn(async move { ship_proofs_to_manufacturer(proofs_clone).await });

    let state = AppState { setup, proofs };

    let app = Router::new()
        .route("/health", get(health))
        .route("/vk", get(vk))
        .route("/proof1", post(proof1))
        .with_state(state);

    let addr: SocketAddr = "0.0.0.0:3001".parse()?;
    tracing::info!("Supplier service listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn vk(State(state): State<AppState>) -> impl IntoResponse {
    match vk_to_hex(&state.setup.inner_vk) {
        Ok(hex) => Json(VkResponse { vk: hex }).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn proof1(
    State(state): State<AppState>,
    Json(req): Json<Proof1Request>,
) -> impl IntoResponse {
    let bid = match BatchId::from_hex(&req.batch_id) {
        Ok(b) => b,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };

    match state.proofs.get(&bid.0) {
        Some((proof, _claim)) => match proof_to_hex(proof) {
            Ok(hex) => Json(Proof1Response {
                proof: hex,
                public_inputs: Proof1PublicInputs {
                    batch_id: bid.to_hex(),
                    claim: "sustainable",
                },
            })
            .into_response(),
            Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        },
        None => (
            StatusCode::NOT_FOUND,
            format!("no Proof₁ for batch {}", bid),
        )
            .into_response(),
    }
}

async fn ship_proofs_to_manufacturer(proofs: Arc<HashMap<u64, (InnerProof, Claim)>>) {
    let client = reqwest::Client::new();
    let url = std::env::var("MANUFACTURER_URL")
        .unwrap_or_else(|_| "http://localhost:3002".to_string());
    let endpoint = format!("{}/ingest", url);

    for _ in 0..60 {
        if client.get(format!("{}/health", url)).send().await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    for (batch_id, (proof, _claim)) in proofs.iter() {
        let proof_hex = match proof_to_hex(proof) {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!("could not hex-encode proof for 0x{:x}: {}", batch_id, e);
                continue;
            }
        };
        let body = IngestRequest {
            batch_id: format!("0x{:x}", batch_id),
            proof: proof_hex,
            claim: "sustainable",
        };
        match client.post(&endpoint).json(&body).send().await {
            Ok(r) if r.status().is_success() => {
                tracing::info!("📦 Shipped Proof₁ for batch 0x{:x} to manufacturer", batch_id);
            }
            Ok(r) => {
                tracing::warn!(
                    "Manufacturer refused ingest for 0x{:x}: {}",
                    batch_id,
                    r.status()
                );
            }
            Err(e) => {
                tracing::warn!("Could not reach manufacturer for 0x{:x}: {}", batch_id, e);
            }
        }
    }
}
