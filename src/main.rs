mod config;
mod health;
mod poller;
mod rpc;
mod template;
mod tp_server;

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use tracing::info;

#[derive(Parser)]
#[command(name = "azcoin-template-provider")]
#[command(version, about = "RPC adapter for azcoind block templates")]
struct Cli {
    /// Path to TOML configuration file.
    #[arg(
        short,
        long,
        default_value = "config/azcoin-template-provider.toml"
    )]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    info!(path = %cli.config.display(), "Loading configuration");
    let cfg = config::Config::load(&cli.config)?;
    info!(
        rpc_url  = %cfg.rpc_url,
        network  = %cfg.network,
        poll_ms  = cfg.poll_interval_ms,
        tp_addr  = %cfg.tp_listen_address,
        "Configuration loaded"
    );

    let client = rpc::RpcClient::new(
        cfg.rpc_url.clone(),
        cfg.rpc_user.clone(),
        cfg.rpc_password.clone(),
    )
    .with_template_rules(cfg.template_rules.clone());

    health::check_rpc_connectivity(&client, &cfg).await?;

    let (template_tx, template_rx) = tokio::sync::watch::channel(None);

    info!(
        tp_address = %cfg.tp_listen_address,
        authority_key_configured = !cfg.authority_public_key.is_empty(),
        "Starting SV2 Template Provider stub"
    );

    tokio::select! {
        res = poller::run(&client, cfg.poll_interval_ms, template_tx) => res,
        res = tp_server::run(&cfg.tp_listen_address, template_rx) => res,
    }
}
