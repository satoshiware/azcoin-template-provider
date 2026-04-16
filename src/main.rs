mod config;
mod health;
mod poller;
mod rpc;
mod template;
mod tp_server;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use tracing::{info, warn};

/// Capacity for `tokio::sync::broadcast` used to push live template updates to SV2 sessions.
/// Larger depth reduces `RecvError::Lagged` / drops when many templates arrive in a burst (0.2.0).
const TEMPLATE_BROADCAST_BUFFER_DEPTH: usize = 512;

#[derive(Parser)]
#[command(name = "azcoin-template-provider")]
#[command(version, about = "AZCOIN SV2 Template Provider — GBT polling, live templates, SubmitSolution → submitblock")]
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

    let client = Arc::new(
        rpc::RpcClient::new(
            cfg.rpc_url.clone(),
            cfg.rpc_user.clone(),
            cfg.rpc_password.clone(),
        )
        .with_template_rules(cfg.template_rules.clone()),
    );

    health::check_rpc_connectivity(client.as_ref(), &cfg).await?;

    let (template_tx, template_rx) = tokio::sync::watch::channel(None);
    let (template_push_tx, _) =
        tokio::sync::broadcast::channel::<crate::template::TemplateUpdatePayload>(
            TEMPLATE_BROADCAST_BUFFER_DEPTH,
        );
    info!(
        template_broadcast_buffer_depth = TEMPLATE_BROADCAST_BUFFER_DEPTH,
        "Template broadcast buffer configured"
    );

    let keys_configured =
        !cfg.authority_public_key.is_empty() && !cfg.authority_secret_key.is_empty();

    if keys_configured {
        info!(
            tp_address = %cfg.tp_listen_address,
            "Starting SV2 Template Provider (Noise-authenticated)"
        );
        let push = template_push_tx.clone();
        let rpc_tp = client.clone();
        tokio::select! {
            res = poller::run(client.as_ref(), cfg.poll_interval_ms, template_tx, push) => res,
            res = tp_server::run(
                &cfg.tp_listen_address,
                &cfg.authority_public_key,
                &cfg.authority_secret_key,
                template_rx,
                template_push_tx,
                rpc_tp,
            ) => res,
        }
    } else {
        warn!("authority keys not configured — SV2 TP listener disabled (poller-only mode)");
        poller::run(
            client.as_ref(),
            cfg.poll_interval_ms,
            template_tx,
            template_push_tx,
        )
        .await
    }
}
