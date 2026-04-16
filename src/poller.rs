//! Template polling loop.
//!
//! Calls `getblocktemplate` every `poll_interval_ms` milliseconds, converts
//! the raw RPC response into an [`AzcoinTemplate`], and compares it to the
//! previous template.  Changes are logged at `INFO`; identical templates are
//! logged at `DEBUG`.
//!
//! Each new template is published through a [`tokio::sync::watch`] channel so
//! [`crate::tp_server`] always has the latest snapshot. **On meaningful change**
//! (see [`AzcoinTemplate::describe_change()`][crate::template::AzcoinTemplate::describe_change]),
//! the same template is also sent on a [`tokio::sync::broadcast`] channel so
//! connected SV2 sessions can roll forward with `NewTemplate` + `SetNewPrevHash`
//! (release **`0.2.0`** behavior).
//!
//! The loop is resilient — a single failed RPC call logs an error and retries
//! on the next tick without crashing the service.

use std::time::Duration;

use anyhow::Result;
use tokio::sync::{broadcast, watch};
use tokio::time;
use tracing::{debug, error, info};

use crate::rpc::RpcClient;
use crate::template::{template_push_fingerprint, AzcoinTemplate, TemplateUpdatePayload};

/// Run the polling loop until the process is terminated.
///
/// Every successfully-parsed template is sent through `template_tx` so that
/// other tasks (e.g. the TP server) can observe the latest state.
pub async fn run(
    client: &RpcClient,
    poll_interval_ms: u64,
    template_tx: watch::Sender<Option<AzcoinTemplate>>,
    template_push_tx: broadcast::Sender<TemplateUpdatePayload>,
) -> Result<()> {
    let interval = Duration::from_millis(poll_interval_ms);
    let mut ticker = time::interval(interval);
    let mut previous: Option<AzcoinTemplate> = None;
    let mut last_push_fp: Option<u64> = None;
    let mut poll_count: u64 = 0;

    info!(interval_ms = poll_interval_ms, "Starting template poller");

    loop {
        ticker.tick().await;
        poll_count += 1;

        let rpc_template = match client.get_block_template().await {
            Ok(t) => t,
            Err(e) => {
                error!(poll = poll_count, "Failed to get block template: {:#}", e);
                continue;
            }
        };

        let template = AzcoinTemplate::from_rpc(&rpc_template);

        match &previous {
            None => {
                info!(
                    poll         = poll_count,
                    height       = template.height,
                    version      = template.version,
                    prev_hash    = %template.previous_block_hash,
                    bits         = %template.bits,
                    tx_count     = template.transactions.len(),
                    coinbase     = template.coinbase_value,
                    total_fees   = template.total_fees(),
                    total_weight = template.total_weight(),
                    "Initial template received"
                );
            }
            Some(prev) => match template.describe_change(prev) {
                Some(description) => {
                    info!(
                        poll      = poll_count,
                        height    = template.height,
                        prev_hash = %template.previous_block_hash,
                        "Template changed: {}",
                        description
                    );
                }
                None => {
                    debug!(poll = poll_count, height = template.height, "Template unchanged");
                }
            },
        }

        let fp = template_push_fingerprint(&template);
        let fp_changed = last_push_fp != Some(fp);
        if fp_changed {
            if last_push_fp.is_some() {
                info!(
                    poll = poll_count,
                    height = template.height,
                    prev_hash = %template.previous_block_hash,
                    fingerprint = fp,
                    "Template change detected (SV2 push fingerprint)"
                );
            }
            let old_height = previous.as_ref().map(|p| p.height);
            let receiver_count = template_push_tx.receiver_count();
            info!(
                poll = poll_count,
                old_height = ?old_height,
                new_height = template.height,
                old_fingerprint = ?last_push_fp,
                new_fingerprint = fp,
                receiver_count = receiver_count,
                "SV2 live broadcast: about to send (pre-send instrumentation)"
            );
            let send_result = template_push_tx.send(TemplateUpdatePayload {
                template: template.clone(),
            });
            match &send_result {
                Ok(n_receivers) => info!(
                    poll = poll_count,
                    receivers_notified = *n_receivers,
                    result = "Ok",
                    "SV2 live broadcast: send result"
                ),
                Err(e) => info!(
                    poll = poll_count,
                    result = "Err",
                    error = ?e,
                    "SV2 live broadcast: send result"
                ),
            }
            match send_result {
                Ok(n) => info!(
                    poll = poll_count,
                    receivers = n,
                    height = template.height,
                    "Template update queued for SV2 pool sessions"
                ),
                Err(_) => debug!(poll = poll_count, "template push channel closed; skip SV2 queue"),
            }
            last_push_fp = Some(fp);
        }

        let _ = template_tx.send(Some(template.clone()));
        previous = Some(template);
    }
}
