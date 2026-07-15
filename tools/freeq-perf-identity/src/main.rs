use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use base64::Engine as _;
use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "freeq-perf-identity")]
#[command(about = "Generate identity/key exchange files for a FreeQ perf test node")]
struct Args {
    #[arg(long)]
    node_name: String,

    #[arg(long, default_value = "10.66.0.2/24")]
    overlay_address: String,

    #[arg(long, default_value = "0.0.0.0:51820")]
    listen: String,

    #[arg(long, default_value = ".freeq-perf")]
    output_dir: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();
    fs::create_dir_all(&args.output_dir).with_context(|| {
        format!(
            "failed to create output directory {}",
            args.output_dir.display()
        )
    })?;

    let identity_path = args.output_dir.join("identity.key");
    let mut rng = rand::thread_rng();
    let (identity, public_key) = freeq_crypto::sign::IdentityKeypair::generate(&mut rng)
        .context("failed to generate FreeQ identity keypair")?;
    let (_kem_secret, kem_public) = freeq_crypto::kem::HybridSecretKey::generate(&mut rng)
        .context("failed to generate FreeQ KEM public key")?;

    fs::write(&identity_path, identity.to_bytes())
        .with_context(|| format!("failed to write identity key {}", identity_path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&identity_path, fs::Permissions::from_mode(0o600))
            .context("failed to restrict identity key permissions")?;
    }

    let public_key_b64 = base64::engine::general_purpose::STANDARD.encode(public_key.to_bytes());
    let kem_key_b64 = base64::engine::general_purpose::STANDARD.encode(kem_public.to_bytes());
    let identity_path_text = identity_path.to_string_lossy().to_string();

    let exchange = serde_json::json!({
        "schema_version": "freeq.perf_node_exchange.v1",
        "node_name": args.node_name.clone(),
        "overlay_address": args.overlay_address.clone(),
        "listen": args.listen.clone(),
        "identity_key_path": identity_path_text,
        "public_key": public_key_b64,
        "kem_key": kem_key_b64
    });
    fs::write(
        args.output_dir.join("node-exchange.json"),
        serde_json::to_string_pretty(&exchange)? + "\n",
    )
    .context("failed to write node-exchange.json")?;

    let env_file = format!(
        "FREEQ_NODE_NAME='{}'\nFREEQ_NODE_ADDRESS='{}'\nFREEQ_NODE_LISTEN='{}'\nFREEQ_IDENTITY_KEY_PATH='{}'\nFREEQ_PUBLIC_KEY_B64='{}'\nFREEQ_KEM_KEY_B64='{}'\n",
        shell_quote_value(&args.node_name),
        shell_quote_value(&args.overlay_address),
        shell_quote_value(&args.listen),
        shell_quote_value(&identity_path_text),
        public_key_b64,
        kem_key_b64
    );
    fs::write(args.output_dir.join("node.env"), env_file).context("failed to write node.env")?;

    let allowed_ip = host_route(&args.overlay_address);
    let snippet = format!(
        "[[peer]]\nname = \"{}\"\nendpoint = \"REPLACE_WITH_REACHABLE_HOST_OR_IP:51820\"\npublic_key = \"{}\"\nkem_key = \"{}\"\nallowed_ips = [\"{}\"]\nkey_rotation_secs = 3600\n",
        args.node_name, public_key_b64, kem_key_b64, allowed_ip
    );
    fs::write(args.output_dir.join("peer-snippet.toml"), snippet)
        .context("failed to write peer-snippet.toml")?;

    println!("FreeQ perf identity generated:");
    println!("  {}", args.output_dir.join("node-exchange.json").display());
    println!("  {}", args.output_dir.join("node.env").display());
    println!("  {}", args.output_dir.join("peer-snippet.toml").display());
    println!();
    println!("Send node-exchange.json or node.env to the other tester over a trusted channel.");
    Ok(())
}

fn shell_quote_value(value: &str) -> String {
    value.replace('\'', "'\\''")
}

fn host_route(cidr: &str) -> String {
    let host = cidr.split('/').next().unwrap_or(cidr);
    format!("{host}/32")
}
