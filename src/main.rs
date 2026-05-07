mod config;
mod health;
mod poller;
mod rpc;
mod template;
mod tp_server;
mod zmq_wakeup;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use tracing::{debug, warn};

/// Capacity for `tokio::sync::broadcast` used to push live template updates to SV2 sessions.
/// Larger depth reduces `RecvError::Lagged` / drops when many templates arrive in a burst (0.2.0).
const TEMPLATE_BROADCAST_BUFFER_DEPTH: usize = 512;

#[derive(Parser)]
#[command(name = "azcoin-template-provider")]
#[command(
    version,
    about = "AZCOIN SV2 Template Provider — GBT polling, live templates, SubmitSolution → submitblock"
)]
struct Cli {
    /// Path to TOML configuration file.
    #[arg(short, long, default_value = "config/azcoin-template-provider.toml")]
    config: PathBuf,
    /// Exit after validating config and verifying azcoind JSON-RPC (+ mainnet chain match).
    #[arg(long)]
    health_check: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_timer(tracing_subscriber::fmt::time::SystemTime)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    debug!(path = %cli.config.display(), "Loading configuration");
    let cfg = config::Config::load(&cli.config)?;
    debug!(
        rpc_url = %cfg.rpc_url,
        poll_ms = cfg.poll_interval_ms,
        tp_addr = %cfg.tp_listen_address,
        expected_network = %config::AZCOIN_EXPECTED_CHAIN,
        template_rules = ?config::azcoin_template_rules_vec(),
        "Configuration loaded (expected chain and GBT rules are compiled in, not from TOML)"
    );

    let client = Arc::new(rpc::RpcClient::new(
        cfg.rpc_url.clone(),
        cfg.rpc_user.clone(),
        cfg.rpc_password.clone(),
    ));

    health::check_rpc_connectivity(client.as_ref(), &cfg).await?;

    if cli.health_check {
        tracing::info!(
            event = "health_check_complete",
            "RPC and AZCoin Core `main` chain validated (health_check); exiting"
        );
        return Ok(());
    }

    let (template_tx, template_rx) = tokio::sync::watch::channel(None);
    let (template_push_tx, _) = tokio::sync::broadcast::channel::<
        crate::template::TemplateUpdatePayload,
    >(TEMPLATE_BROADCAST_BUFFER_DEPTH);
    debug!(
        template_broadcast_buffer_depth = TEMPLATE_BROADCAST_BUFFER_DEPTH,
        "Template broadcast channel initialized"
    );

    let keys_configured =
        !cfg.authority_public_key.is_empty() && !cfg.authority_secret_key.is_empty();

    tracing::info!(
        event = "template_provider_startup",
        version = env!("CARGO_PKG_VERSION"),
        config_path = %cli.config.display(),
        rpc_url = %cfg.rpc_url,
        expected_network = %config::AZCOIN_EXPECTED_CHAIN,
        template_rules = ?config::azcoin_template_rules_vec(),
        poll_interval_ms = cfg.poll_interval_ms,
        tp_listen_address = %cfg.tp_listen_address,
        sv2_tp_enabled = keys_configured,
        zmq_enabled = cfg.zmq_enabled,
        "template provider wiring complete — starting main tasks"
    );

    let zmq_wakeup_rx = if cfg.zmq_enabled {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let recv_timeout = cfg
            .zmq_receive_timeout_ms
            .try_into()
            .unwrap_or(i32::MAX)
            .clamp(1, i32::MAX);
        let zmq_thread_cfg = zmq_wakeup::ZmqThreadConfig {
            endpoint: cfg.zmq_endpoint.clone(),
            subscribe_hashblock: cfg.zmq_subscribe_hashblock,
            subscribe_sequence: cfg.zmq_subscribe_sequence,
            receive_timeout_ms: recv_timeout,
            reconnect_backoff_ms: cfg.zmq_reconnect_backoff_ms,
        };
        let _zmq_join = zmq_wakeup::spawn_zmq_thread(zmq_thread_cfg, tx);
        Some(rx)
    } else {
        None
    };

    if keys_configured {
        debug!(
            tp_address = %cfg.tp_listen_address,
            "Starting SV2 listener + poller (Noise-authenticated Template Distribution)"
        );
        let push = template_push_tx.clone();
        let rpc_tp = client.clone();
        tokio::select! {
            res = poller::run(
                client.as_ref(),
                cfg.poll_interval_ms,
                zmq_wakeup_rx,
                cfg.zmq_wakeup_debounce_ms,
                template_tx,
                push,
            ) => res,
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
            zmq_wakeup_rx,
            cfg.zmq_wakeup_debounce_ms,
            template_tx,
            template_push_tx,
        )
        .await
    }
}
