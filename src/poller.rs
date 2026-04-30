//! Template polling loop.
//!
//! Calls `getblocktemplate` every `poll_interval_ms` milliseconds, converts
//! the raw RPC response into an [`AzcoinTemplate`], and compares it to the
//! previous template.  Stable `event=` fields are emitted at **`INFO`**; redundant
//! broadcaster bookkeeping logs are **`DEBUG`**. Identical consecutive templates stay **`DEBUG`**.
//!
//! Each new template is published through a [`tokio::sync::watch`] channel so
//! [`crate::tp_server`] always has the latest snapshot. **On meaningful change**
//! (see [`AzcoinTemplate::describe_change()`][crate::template::AzcoinTemplate::describe_change]),
//! the same template is also sent on a [`tokio::sync::broadcast`] channel so
//! connected SV2 sessions can roll forward with `NewTemplate` + `SetNewPrevHash`
//! (release **`0.2.0`** stable behavior).
//!
//! The loop is resilient — a single failed RPC call logs an error and retries
//! on the next tick without crashing the service.

use std::time::Duration;

use anyhow::Result;
use tokio::sync::{broadcast, watch};
use tokio::time;
use tracing::{debug, error, info};

use crate::rpc::RpcClient;
use crate::template::{
    template_push_fingerprint, AzcoinTemplate, TemplateSnapshot, TemplateUpdatePayload,
};

/// Run the polling loop until the process is terminated.
///
/// Every successfully-parsed template is sent through `template_tx` so that
/// other tasks (e.g. the TP server) can observe the latest state.
pub async fn run(
    client: &RpcClient,
    poll_interval_ms: u64,
    template_tx: watch::Sender<Option<TemplateSnapshot>>,
    template_push_tx: broadcast::Sender<TemplateUpdatePayload>,
) -> Result<()> {
    let interval = Duration::from_millis(poll_interval_ms);
    let mut ticker = time::interval(interval);
    let mut previous: Option<TemplateSnapshot> = None;
    let mut last_push_fp: Option<u64> = None;
    let mut next_template_id: u64 = 1;
    let mut poll_count: u64 = 0;

    debug!(
        interval_ms = poll_interval_ms,
        "Starting template poller loop"
    );

    loop {
        ticker.tick().await;
        poll_count += 1;

        let rpc_template = match client.get_block_template().await {
            Ok(t) => t,
            Err(e) => {
                error!(
                    event = "azcoin_rpc_error",
                    method = "getblocktemplate",
                    poll = poll_count,
                    "RPC getblocktemplate failed: {:#}",
                    e
                );
                continue;
            }
        };

        let template = AzcoinTemplate::from_rpc(&rpc_template);

        match previous.as_ref().map(|p| &p.template) {
            None => {
                info!(
                    event = "template_changed",
                    change_kind = "first_poll_precache",
                    poll         = poll_count,
                    height       = template.height,
                    template_id_known = false,
                    version      = template.version,
                    previous_block_hash    = %template.previous_block_hash,
                    bits         = %template.bits,
                    tx_count     = template.transactions.len(),
                    coinbase     = template.coinbase_value,
                    total_fees   = template.total_fees(),
                    total_weight = template.total_weight(),
                    witness_commitment_included = template.witness_commitment_included(),
                    coinbase_output_count = template.sv2_placeholder_coinbase_output_count(),
                    "Initial template from node (SV2 template_id assigned after fingerprint step)"
                );
            }
            Some(prev) => match template.describe_change(prev) {
                Some(description) => {
                    info!(
                        event = "template_changed",
                        change_kind = "describe_change",
                        poll      = poll_count,
                        prior_template_id = ?previous.as_ref().map(|s| s.template_id),
                        height    = template.height,
                        previous_block_hash = %template.previous_block_hash,
                        witness_commitment_included = template.witness_commitment_included(),
                        coinbase_output_count = template.sv2_placeholder_coinbase_output_count(),
                        "{}",
                        description
                    );
                }
                None => {
                    debug!(
                        poll = poll_count,
                        height = template.height,
                        "Template unchanged"
                    );
                }
            },
        }

        let fp = template_push_fingerprint(&template);
        let fp_changed = last_push_fp != Some(fp);
        let snapshot = if fp_changed {
            let template_id = next_template_id;
            next_template_id = next_template_id
                .checked_add(1)
                .expect("template_id allocator exhausted u64 space");
            let snapshot = TemplateSnapshot {
                template_id,
                template: template.clone(),
            };
            if last_push_fp.is_none() {
                info!(
                    event = "template_loaded",
                    poll = poll_count,
                    template_id = snapshot.template_id,
                    height = template.height,
                    previous_block_hash = %template.previous_block_hash,
                    witness_commitment_included = template.witness_commitment_included(),
                    coinbase_output_count = template.sv2_placeholder_coinbase_output_count(),
                    "GBT template promoted to tracked SV2 snapshot"
                );
            } else {
                info!(
                    event = "template_changed",
                    change_kind = "sv2_push_fingerprint",
                    poll = poll_count,
                    height = template.height,
                    previous_block_hash = %template.previous_block_hash,
                    fingerprint = fp,
                    template_id = snapshot.template_id,
                    witness_commitment_included = template.witness_commitment_included(),
                    coinbase_output_count = template.sv2_placeholder_coinbase_output_count(),
                    "Template change detected (SV2 push fingerprint)"
                );
            }
            let old_height = previous.as_ref().map(|p| p.template.height);
            let receiver_count = template_push_tx.receiver_count();
            debug!(
                poll = poll_count,
                old_height = ?old_height,
                new_height = template.height,
                old_fingerprint = ?last_push_fp,
                new_fingerprint = fp,
                template_id = snapshot.template_id,
                receiver_count = receiver_count,
                "SV2 broadcast queue: enqueue template update"
            );
            let send_result = template_push_tx.send(TemplateUpdatePayload {
                snapshot: snapshot.clone(),
            });
            match &send_result {
                Ok(n_receivers) => debug!(
                    poll = poll_count,
                    template_id = snapshot.template_id,
                    receivers_notified = *n_receivers,
                    result = "Ok",
                    "SV2 broadcast: send_complete"
                ),
                Err(e) => debug!(
                    poll = poll_count,
                    template_id = snapshot.template_id,
                    result = "Err",
                    error = ?e,
                    "SV2 broadcast: send_complete"
                ),
            }
            match send_result {
                Ok(n) => debug!(
                    poll = poll_count,
                    receivers = n,
                    template_id = snapshot.template_id,
                    height = template.height,
                    "SV2 broadcast: template update dispatched to subscribed sessions"
                ),
                Err(_) => debug!(
                    poll = poll_count,
                    "template push channel closed; skip SV2 queue"
                ),
            }
            last_push_fp = Some(fp);
            snapshot
        } else {
            let template_id = previous
                .as_ref()
                .map(|p| p.template_id)
                .expect("initial template must allocate a template_id");
            TemplateSnapshot {
                template_id,
                template: template.clone(),
            }
        };

        let _ = template_tx.send(Some(snapshot.clone()));
        previous = Some(snapshot);
    }
}
