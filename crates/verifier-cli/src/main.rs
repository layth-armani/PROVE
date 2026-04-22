use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use rand::Rng;
use serde::{Deserialize, Serialize};

use zkp_core::{
    prove::manufacturer_public_inputs, proof_from_hex, verify_manufacturer, vk_from_hex, BatchId,
    Claim, OuterCurve, OuterVerifyingKey,
};

#[derive(Parser, Debug)]
#[command(name = "verifier-cli", about = "EU verifier for the PROVE battery passport")]
enum Cli {
    /// Request and verify a Proof₂ from the manufacturer.
    Verify {
        #[arg(long)]
        batch_id: String,
        #[arg(long, default_value = "sustainable")]
        claim: String,
        #[arg(long, default_value_t = false)]
        force_swap: bool,
        #[arg(long, default_value_t = false)]
        force_forge: bool,
        #[arg(long, default_value = "http://localhost:3002")]
        manufacturer_url: String,
    },
}

#[derive(Serialize)]
struct VerifyRequest<'a> {
    batch_id: &'a str,
    claim: &'a str,
    nonce: u64,
    force_swap: bool,
    force_forge: bool,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct VerifyPublicInputs {
    batch_id: String,
    claim: String,
    nonce: u64,
}

#[derive(Deserialize)]
struct VerifyResponse {
    proof2: String,
    public_inputs: VerifyPublicInputs,
}

#[derive(Deserialize)]
struct VkResponse {
    vk: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warn,verifier_cli=info".into()),
        )
        .init();

    match Cli::parse() {
        Cli::Verify {
            batch_id,
            claim,
            force_swap,
            force_forge,
            manufacturer_url,
        } => {
            run_verify(batch_id, claim, force_swap, force_forge, manufacturer_url).await
        }
    }
}

async fn run_verify(
    batch_id: String,
    claim: String,
    force_swap: bool,
    force_forge: bool,
    manufacturer_url: String,
) -> anyhow::Result<()> {
    let bid = BatchId::from_hex(&batch_id)?;
    let claim_parsed = match claim.as_str() {
        "sustainable" => Claim::Sustainable,
        other => anyhow::bail!("unknown claim '{}'", other),
    };

    println!("{}", "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".dimmed());
    println!(
        "{} verifying {} for claim {}",
        "🇪🇺 EU".bold(),
        format!("batch {}", bid).yellow(),
        claim.cyan()
    );

    let nonce: u64 = rand::thread_rng().gen();
    println!("   nonce = {}", format!("{:#x}", nonce).dimmed());

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()?;

    let outer_vk = fetch_or_cache_vk(&client, &manufacturer_url).await?;

    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::with_template("{spinner:.green} {msg}")
            .unwrap_or_else(|_| ProgressStyle::default_spinner()),
    );
    spinner.set_message("Requesting Proof₂ from manufacturer…");
    spinner.enable_steady_tick(Duration::from_millis(100));

    let body = VerifyRequest {
        batch_id: &batch_id,
        claim: &claim,
        nonce,
        force_swap,
        force_forge,
    };

    let resp = client
        .post(format!("{}/verify", manufacturer_url))
        .json(&body)
        .send()
        .await?;

    let status = resp.status();
    if !status.is_success() {
        spinner.finish_and_clear();
        let text = resp.text().await.unwrap_or_default();
        if status == reqwest::StatusCode::NOT_FOUND {
            println!(
                "{} {} ({})",
                "✗".red().bold(),
                "CANNOT PROVE".red().bold(),
                text.dimmed()
            );
        } else if status == reqwest::StatusCode::UNPROCESSABLE_ENTITY {
            let msg = if force_swap {
                "INVALID (swap detected)"
            } else {
                "CANNOT PROVE"
            };
            println!("{} {} ({})", "✗".red().bold(), msg.red().bold(), text.dimmed());
        } else {
            println!("{} manufacturer error {}: {}", "✗".red().bold(), status, text);
        }
        std::process::exit(1);
    }

    let data: VerifyResponse = resp.json().await?;
    spinner.set_message("Verifying Proof₂ locally…");

    let proof = proof_from_hex::<OuterCurve>(&data.proof2);
    let result = match proof {
        Ok(p) => {
            let pub_inputs = manufacturer_public_inputs(bid, claim_parsed, nonce);
            verify_manufacturer(&outer_vk, &p, &pub_inputs)
        }
        Err(e) => Err(e),
    };

    spinner.finish_and_clear();

    match result {
        Ok(true) => {
            println!("{} {}", "✔".green().bold(), "VALID".green().bold());
            println!("   Proof₂ verified with cryptographic certainty; no secrets were revealed.");
        }
        Ok(false) => {
            println!(
                "{} {} (verifier rejected the proof)",
                "✗".red().bold(),
                "INVALID".red().bold()
            );
            std::process::exit(1);
        }
        Err(e) => {
            println!(
                "{} {} ({})",
                "✗".red().bold(),
                "INVALID".red().bold(),
                e.to_string().dimmed()
            );
            std::process::exit(1);
        }
    }

    Ok(())
}

async fn fetch_or_cache_vk(
    client: &reqwest::Client,
    manufacturer_url: &str,
) -> anyhow::Result<OuterVerifyingKey> {
    let cache_path = PathBuf::from("data/keys/outer_vk.hex");
    if let Ok(hex_text) = std::fs::read_to_string(&cache_path) {
        if let Ok(vk) = vk_from_hex::<OuterCurve>(hex_text.trim()) {
            return Ok(vk);
        }
    }

    let resp: VkResponse = client
        .get(format!("{}/vk_outer", manufacturer_url))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let vk = vk_from_hex::<OuterCurve>(&resp.vk)?;

    if let Some(parent) = cache_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&cache_path, &resp.vk);

    Ok(vk)
}
