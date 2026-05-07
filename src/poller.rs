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
//! Optional AZCoin Core ZMQ topics (`hashblock`, `sequence`) may wake the same
//! refresh path between poll ticks; ZMQ payloads are **not** parsed for template
//! truth — `getblocktemplate` remains authoritative.
//!
//! The loop is resilient — a single failed RPC call logs an error and retries
//! on the next tick without crashing the service.

use std::time::Duration;

use anyhow::Result;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::{broadcast, watch};
use tokio::time::{self, Instant};
use tracing::{debug, error, info, warn};

use crate::rpc::RpcClient;
use crate::template::{
    template_push_fingerprint, AzcoinTemplate, TemplateSnapshot, TemplateUpdatePayload,
};
use crate::zmq_wakeup::{merge_zmq_pending, ZmqWakeupKind};

/// Why a `getblocktemplate` refresh was scheduled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TemplateRefreshReason {
    Poll,
    ZmqHashblock,
    ZmqSequence,
}

impl TemplateRefreshReason {
    fn as_reason_str(&self) -> &'static str {
        match self {
            TemplateRefreshReason::Poll => "poll",
            TemplateRefreshReason::ZmqHashblock => "zmq_hashblock",
            TemplateRefreshReason::ZmqSequence => "zmq_sequence",
        }
    }
}

fn zmq_kind_to_refresh(k: ZmqWakeupKind) -> TemplateRefreshReason {
    match k {
        ZmqWakeupKind::Hashblock => TemplateRefreshReason::ZmqHashblock,
        ZmqWakeupKind::Sequence => TemplateRefreshReason::ZmqSequence,
    }
}

/// Run the polling loop until the process is terminated.
///
/// Every successfully-parsed template is sent through `template_tx` so that
/// other tasks (e.g. the TP server) can observe the latest state.
///
/// When `zmq_wakeup_rx` is `Some`, debounced ZMQ signals run the same refresh
/// path as the poll timer. When `None`, behavior matches the historical
/// poll-only loop.
pub async fn run(
    client: &RpcClient,
    poll_interval_ms: u64,
    zmq_wakeup_rx: Option<UnboundedReceiver<ZmqWakeupKind>>,
    zmq_wakeup_debounce_ms: u64,
    template_tx: watch::Sender<Option<TemplateSnapshot>>,
    template_push_tx: broadcast::Sender<TemplateUpdatePayload>,
) -> Result<()> {
    let Some(mut zmq_rx) = zmq_wakeup_rx else {
        info!(
            event = "zmq_disabled",
            "ZMQ template wakeup disabled (poll_interval_ms backup only)"
        );
        return run_poll_only(client, poll_interval_ms, template_tx, template_push_tx).await;
    };
    let debounce = Duration::from_millis(zmq_wakeup_debounce_ms.max(1));
    const FAR: Duration = Duration::from_secs(365 * 86400 * 10);
    let mut debounce_sleep = Box::pin(time::sleep_until(Instant::now() + FAR));
    let mut pending_zmq: Option<ZmqWakeupKind> = None;
    let mut zmq_alive = true;

    let interval = Duration::from_millis(poll_interval_ms);
    let mut ticker = time::interval(interval);
    let mut previous: Option<TemplateSnapshot> = None;
    let mut last_push_fp: Option<u64> = None;
    let mut next_template_id: u64 = 1;
    let mut poll_count: u64 = 0;

    debug!(
        interval_ms = poll_interval_ms,
        zmq_debounce_ms = zmq_wakeup_debounce_ms,
        "Starting template poller loop (poll + ZMQ wakeup)"
    );

    loop {
        tokio::select! {
            biased;
            _ = ticker.tick() => {
                poll_count += 1;
                debug!(
                    event = "template_refresh_trigger",
                    reason = TemplateRefreshReason::Poll.as_reason_str(),
                    poll = poll_count,
                    "scheduling template refresh"
                );
                refresh_from_rpc(
                    client,
                    poll_count,
                    &mut previous,
                    &mut last_push_fp,
                    &mut next_template_id,
                    &template_tx,
                    &template_push_tx,
                )
                .await;
            }
            msg = zmq_rx.recv(), if zmq_alive => {
                match msg {
                    Some(k) => {
                        pending_zmq = Some(merge_zmq_pending(pending_zmq.take(), k));
                        debounce_sleep
                            .as_mut()
                            .reset(Instant::now() + debounce);
                    }
                    None => {
                        warn!(
                            event = "zmq_error",
                            "ZMQ wakeup channel dropped; continuing with poll_interval_ms backup only"
                        );
                        zmq_alive = false;
                        pending_zmq = None;
                        debounce_sleep
                            .as_mut()
                            .reset(Instant::now() + FAR);
                    }
                }
            }
            _ = debounce_sleep.as_mut(), if pending_zmq.is_some() => {
                let merged = pending_zmq.take().expect("guarded by select if");
                let reason = zmq_kind_to_refresh(merged);
                poll_count += 1;
                debug!(
                    event = "template_refresh_trigger",
                    reason = reason.as_reason_str(),
                    poll = poll_count,
                    "scheduling template refresh (debounced ZMQ)"
                );
                refresh_from_rpc(
                    client,
                    poll_count,
                    &mut previous,
                    &mut last_push_fp,
                    &mut next_template_id,
                    &template_tx,
                    &template_push_tx,
                )
                .await;
                debounce_sleep
                    .as_mut()
                    .reset(Instant::now() + FAR);
            }
        }
    }
}

async fn run_poll_only(
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
        debug!(
            event = "template_refresh_trigger",
            reason = TemplateRefreshReason::Poll.as_reason_str(),
            poll = poll_count,
            "scheduling template refresh"
        );
        refresh_from_rpc(
            client,
            poll_count,
            &mut previous,
            &mut last_push_fp,
            &mut next_template_id,
            &template_tx,
            &template_push_tx,
        )
        .await;
    }
}

async fn refresh_from_rpc(
    client: &RpcClient,
    poll_count: u64,
    previous: &mut Option<TemplateSnapshot>,
    last_push_fp: &mut Option<u64>,
    next_template_id: &mut u64,
    template_tx: &watch::Sender<Option<TemplateSnapshot>>,
    template_push_tx: &broadcast::Sender<TemplateUpdatePayload>,
) {
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
            return;
        }
    };

    let template = AzcoinTemplate::from_rpc(&rpc_template);
    ingest_azcoin_template(
        template,
        poll_count,
        previous,
        last_push_fp,
        next_template_id,
        template_tx,
        template_push_tx,
    );
}

fn ingest_azcoin_template(
    template: AzcoinTemplate,
    poll_count: u64,
    previous: &mut Option<TemplateSnapshot>,
    last_push_fp: &mut Option<u64>,
    next_template_id: &mut u64,
    template_tx: &watch::Sender<Option<TemplateSnapshot>>,
    template_push_tx: &broadcast::Sender<TemplateUpdatePayload>,
) {
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
    let fp_changed = *last_push_fp != Some(fp);
    let snapshot = if fp_changed {
        let template_id = *next_template_id;
        *next_template_id = next_template_id
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
            old_fingerprint = ?*last_push_fp,
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
        *last_push_fp = Some(fp);
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
    *previous = Some(snapshot);
}

#[cfg(test)]
mod refresh_tests {
    use super::*;
    use crate::template::TemplateTx;

    fn stub_template(prev_hash: &str, height: u64) -> AzcoinTemplate {
        AzcoinTemplate {
            height,
            version: 0x20000000,
            previous_block_hash: prev_hash.to_string(),
            bits: "207fffff".to_string(),
            target: "00000000".to_string(),
            curtime: 1,
            mintime: 0,
            coinbase_value: 5_000_000_000,
            size_limit: 0,
            weight_limit: 0,
            sigop_limit: 0,
            default_witness_commitment: None,
            transactions: vec![TemplateTx {
                txid: "a".repeat(64),
                fee: 0,
                weight: 0,
                sigops: 0,
                data: String::new(),
            }],
        }
    }

    #[test]
    fn identical_template_twice_does_not_broadcast_twice() {
        let t = stub_template(
            "0000000000000000000000000000000000000000000000000000000000000001",
            1,
        );
        let (push_tx, _) = broadcast::channel::<TemplateUpdatePayload>(16);
        let mut sub = push_tx.subscribe();
        let (watch_tx, _watch_rx) = watch::channel(None);
        let mut previous = None;
        let mut last_fp = None;
        let mut next_tid = 1u64;

        ingest_azcoin_template(
            t.clone(),
            1,
            &mut previous,
            &mut last_fp,
            &mut next_tid,
            &watch_tx,
            &push_tx,
        );
        assert!(
            sub.try_recv().is_ok(),
            "first fingerprint allocates a broadcast"
        );

        ingest_azcoin_template(
            t.clone(),
            2,
            &mut previous,
            &mut last_fp,
            &mut next_tid,
            &watch_tx,
            &push_tx,
        );
        assert!(
            matches!(
                sub.try_recv(),
                Err(tokio::sync::broadcast::error::TryRecvError::Empty)
            ),
            "duplicate fingerprint must skip SV2 broadcast"
        );
    }
}
