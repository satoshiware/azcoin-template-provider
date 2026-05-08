mod config;
mod health;
mod poller;
mod rpc;
mod template;
mod tp_server;
mod zmq_wakeup;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{Context as _, Result};
use clap::Parser;
use tracing::debug;
use tracing_subscriber::prelude::*;
use tracing_subscriber::util::SubscriberInitExt;

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

#[derive(Clone)]
struct SharedFileWriter(Arc<Mutex<std::fs::File>>);

impl std::io::Write for SharedFileWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("log file mutex poisoned").write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.lock().expect("log file mutex poisoned").flush()
    }
}

fn init_tracing(log_file: &str) -> Result<()> {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    let stdout_layer = tracing_subscriber::fmt::layer()
        .with_timer(tracing_subscriber::fmt::time::SystemTime)
        .with_writer(std::io::stdout);

    let subscriber = tracing_subscriber::registry()
        .with(env_filter)
        .with(stdout_layer);

    if log_file.trim().is_empty() {
        subscriber.init();
        return Ok(());
    }

    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_file)
        .with_context(|| format!("failed to open log_file: {log_file}"))?;

    let shared = Arc::new(Mutex::new(file));
    let file_writer = SharedFileWriter(shared.clone());
    let file_layer = tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .with_timer(tracing_subscriber::fmt::time::SystemTime)
        .with_writer(move || file_writer.clone());

    subscriber.with(file_layer).init();

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let cfg = config::Config::load(&cli.config)?;
    init_tracing(cfg.log_file.as_str())?;

    debug!(
        path = %cli.config.display(),
        log_file_active = %(!cfg.log_file.trim().is_empty()),
        zmq_endpoint_rawtx = %cfg.zmq_endpoint_rawtx,
        zmq_endpoint_hashblock = %cfg.zmq_endpoint_hashblock,
        zmq_endpoint_sequence = %cfg.zmq_endpoint_sequence,
        fee_threshold = cfg.fee_threshold,
        max_template_transactions = cfg.max_template_transactions,
        "Configuration loaded (expected chain / GBT rules compiled into binary)"
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
        fee_threshold = cfg.fee_threshold,
        max_template_transactions = cfg.max_template_transactions,
        zmq_wakeup = true,
        zmq_endpoint_rawtx = %cfg.zmq_endpoint_rawtx,
        zmq_endpoint_hashblock = %cfg.zmq_endpoint_hashblock,
        zmq_endpoint_sequence = %cfg.zmq_endpoint_sequence,
        log_file_configured = %(!cfg.log_file.trim().is_empty()),
        "template provider wiring complete — starting main tasks"
    );

    let (zmq_wakeup_tx, zmq_wakeup_rx) = tokio::sync::mpsc::unbounded_channel();
    let recv_timeout = cfg
        .zmq_receive_timeout_ms
        .try_into()
        .unwrap_or(i32::MAX)
        .clamp(1, i32::MAX);
    let zmq_thread_cfg = zmq_wakeup::ZmqThreadConfig {
        endpoint_rawtx: cfg.zmq_endpoint_rawtx.clone(),
        endpoint_hashblock: cfg.zmq_endpoint_hashblock.clone(),
        endpoint_sequence: cfg.zmq_endpoint_sequence.clone(),
        receive_timeout_ms: recv_timeout,
        reconnect_backoff_ms: cfg.zmq_reconnect_backoff_ms,
    };
    let _zmq_join = zmq_wakeup::spawn_zmq_thread(zmq_thread_cfg, zmq_wakeup_tx);

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
                cfg.fee_threshold,
                cfg.max_template_transactions,
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
        tracing::warn!(
            authority_keys_missing = true,
            "authority keys not configured — SV2 TP listener disabled (poller-only mode)"
        );
        poller::run(
            client.as_ref(),
            cfg.poll_interval_ms,
            zmq_wakeup_rx,
            cfg.zmq_wakeup_debounce_ms,
            cfg.fee_threshold,
            cfg.max_template_transactions,
            template_tx,
            template_push_tx,
        )
        .await
    }
}
