//! Template polling loop.
//!
//! Calls `getblocktemplate` every `poll_interval_ms` milliseconds, converts
//! the raw RPC response into an [`AzcoinTemplate`], and compares it to the
//! previous template.  Stable `event=` fields are emitted at **`INFO`**; redundant
//! broadcaster bookkeeping logs are **`DEBUG`**. Identical consecutive templates stay **`DEBUG`**.
//!
//! Each new template snapshot is published through a [`tokio::sync::watch`] channel so
//! [`crate::tp_server`] always tracks the latest **accepted** snapshot. **`broadcast`**
//! is used **only when** a mempool or chain-tip update qualifies per `fee_threshold` /
//! [`max_template_transactions`](crate::config::Config::max_template_transactions) rules
//! (**tip-change pushes ignore both fee delta and txn-count cap — see README / runbook**).
//!
//! AZCoin Core ZMQ topics (`rawtx`, `hashblock`, `sequence`) schedule extra
//! `getblocktemplate` wakeups; ZMQ payloads are **not** parsed for template
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
    ZmqRawtx,
    ZmqHashblock,
    ZmqSequence,
}

impl TemplateRefreshReason {
    fn as_reason_str(&self) -> &'static str {
        match self {
            TemplateRefreshReason::Poll => "poll",
            TemplateRefreshReason::ZmqRawtx => "zmq_rawtx",
            TemplateRefreshReason::ZmqHashblock => "zmq_hashblock",
            TemplateRefreshReason::ZmqSequence => "zmq_sequence",
        }
    }
}

fn zmq_kind_to_refresh_reason(k: ZmqWakeupKind) -> TemplateRefreshReason {
    match k {
        ZmqWakeupKind::Rawtx => TemplateRefreshReason::ZmqRawtx,
        ZmqWakeupKind::Hashblock => TemplateRefreshReason::ZmqHashblock,
        ZmqWakeupKind::Sequence => TemplateRefreshReason::ZmqSequence,
    }
}

/// Run the polling loop until the process is terminated.
///
/// Poll timer + optional debounced ZMQ wakeups invoke the same authoritative
/// [`getblocktemplate`] path; ZMQ payloads are wakeup hints only.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    client: &RpcClient,
    poll_interval_ms: u64,
    mut zmq_wakeup_rx: UnboundedReceiver<ZmqWakeupKind>,
    zmq_wakeup_debounce_ms: u64,
    fee_threshold: u64,
    max_template_transactions: u64,
    template_tx: watch::Sender<Option<TemplateSnapshot>>,
    template_push_tx: broadcast::Sender<TemplateUpdatePayload>,
) -> Result<()> {
    let debounce = Duration::from_millis(zmq_wakeup_debounce_ms.max(1));
    const FAR: Duration = Duration::from_secs(365 * 86400 * 10);
    let mut debounce_sleep = Box::pin(time::sleep_until(Instant::now() + FAR));
    let mut pending_zmq: Option<ZmqWakeupKind> = None;
    let mut zmq_alive = true;

    let interval = Duration::from_millis(poll_interval_ms);
    let mut ticker = time::interval(interval);
    let mut previous: Option<TemplateSnapshot> = None;
    let mut last_seen_gbt: Option<AzcoinTemplate> = None;
    let mut last_broadcast: Option<TemplateSnapshot> = None;
    let mut last_push_fp: Option<u64> = None;
    let mut next_template_id: u64 = 1;
    let mut poll_count: u64 = 0;

    debug!(
        interval_ms = poll_interval_ms,
        zmq_debounce_ms = zmq_wakeup_debounce_ms,
        fee_threshold,
        max_template_transactions,
        "Starting template poller loop (poll + ZMQ wakeup; push policy applied)"
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
                    TemplateRefreshReason::Poll,
                    poll_count,
                    fee_threshold,
                    max_template_transactions,
                    &mut previous,
                    &mut last_seen_gbt,
                    &mut last_broadcast,
                    &mut last_push_fp,
                    &mut next_template_id,
                    &template_tx,
                    &template_push_tx,
                )
                .await;
            }
            msg = zmq_wakeup_rx.recv(), if zmq_alive => {
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
                            polling_fallback_active = true,
                            "ZMQ wakeup channel dropped — continuing getblocktemplate polls only"
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
                let reason = zmq_kind_to_refresh_reason(merged);
                poll_count += 1;
                debug!(
                    event = "template_refresh_trigger",
                    reason = reason.as_reason_str(),
                    poll = poll_count,
                    "scheduling template refresh (debounced ZMQ)"
                );
                refresh_from_rpc(
                    client,
                    reason,
                    poll_count,
                    fee_threshold,
                    max_template_transactions,
                    &mut previous,
                    &mut last_seen_gbt,
                    &mut last_broadcast,
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

#[allow(clippy::too_many_arguments)]
async fn refresh_from_rpc(
    client: &RpcClient,
    refresh_reason: TemplateRefreshReason,
    poll_count: u64,
    fee_threshold: u64,
    max_template_transactions: u64,
    previous: &mut Option<TemplateSnapshot>,
    last_seen_gbt: &mut Option<AzcoinTemplate>,
    last_broadcast: &mut Option<TemplateSnapshot>,
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
                refresh_reason = refresh_reason.as_reason_str(),
                "RPC getblocktemplate failed: {:#}",
                e
            );
            return;
        }
    };

    let template = AzcoinTemplate::from_rpc(&rpc_template);
    ingest_azcoin_template(
        template,
        refresh_reason,
        poll_count,
        fee_threshold,
        max_template_transactions,
        previous,
        last_seen_gbt,
        last_broadcast,
        last_push_fp,
        next_template_id,
        template_tx,
        template_push_tx,
    );
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::cognitive_complexity)]
fn ingest_azcoin_template(
    template: AzcoinTemplate,
    refresh_reason: TemplateRefreshReason,
    poll_count: u64,
    fee_threshold: u64,
    max_template_transactions: u64,
    previous: &mut Option<TemplateSnapshot>,
    last_seen_gbt: &mut Option<AzcoinTemplate>,
    last_broadcast: &mut Option<TemplateSnapshot>,
    last_push_fp: &mut Option<u64>,
    next_template_id: &mut u64,
    template_tx: &watch::Sender<Option<TemplateSnapshot>>,
    template_push_tx: &broadcast::Sender<TemplateUpdatePayload>,
) {
    let describe_against = last_seen_gbt.as_ref();

    match describe_against {
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
                    refresh_reason = refresh_reason.as_reason_str(),
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
                    refresh_reason = refresh_reason.as_reason_str(),
                    height = template.height,
                    "Template unchanged vs last GBT (curtime drift ignored)"
                );
            }
        },
    }

    *last_seen_gbt = Some(template.clone());

    let fp = template_push_fingerprint(&template);
    let max_tx_usize = max_template_transactions as usize;

    let tip_change_vs_last_push = match last_broadcast.as_ref() {
        None => true,
        Some(broadcast) => {
            template.previous_block_hash != broadcast.template.previous_block_hash
                || template.height != broadcast.template.height
        }
    };

    // Broadcast when chain tip rolled forward (`tip_changed`), or mempool delta qualifies.
    let do_push = if last_broadcast.is_none() || tip_change_vs_last_push {
        true
    } else if Some(fp) == *last_push_fp {
        false
    } else {
        let last_fees = last_broadcast
            .as_ref()
            .map(|s| s.template.total_fees())
            .unwrap_or(0);
        let total_fees = template.total_fees();
        let fee_delta = total_fees.saturating_sub(last_fees);
        let tx_count = template.transactions.len();

        if fee_delta < fee_threshold {
            debug!(
                event = "template_update_suppressed",
                reason = "fee_delta_below_threshold",
                fee_delta,
                fee_threshold,
                total_fees,
                height = template.height,
                previous_block_hash = %template.previous_block_hash,
                poll = poll_count,
                refresh_reason = refresh_reason.as_reason_str(),
                "mempool-driven template refresh did not qualify for broadcast"
            );
            false
        } else if tx_count > max_tx_usize {
            warn!(
                event = "template_rejected",
                reason = "max_template_transactions_exceeded",
                tx_count,
                max_template_transactions,
                total_fees,
                fee_delta,
                height = template.height,
                previous_block_hash = %template.previous_block_hash,
                refresh_reason = refresh_reason.as_reason_str(),
                "mempool-qualified template suppressed — transaction count exceeds cap"
            );
            false
        } else {
            true
        }
    };

    if !do_push {
        if let Some(b) = last_broadcast.clone() {
            let _ = template_tx.send(Some(b.clone()));
            *previous = Some(b);
        }
        return;
    }

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
                refresh_reason = refresh_reason.as_reason_str(),
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
                refresh_reason = refresh_reason.as_reason_str(),
                height = template.height,
                previous_block_hash = %template.previous_block_hash,
                fingerprint = fp,
                template_id = snapshot.template_id,
                witness_commitment_included = template.witness_commitment_included(),
                coinbase_output_count = template.sv2_placeholder_coinbase_output_count(),
                "Template change accepted for SV2 push (fingerprint)",
            );
        }
        let receiver_count = template_push_tx.receiver_count();
        debug!(
            poll = poll_count,
            refresh_reason = refresh_reason.as_reason_str(),
            template_id = snapshot.template_id,
            receiver_count,
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
                refresh_reason = refresh_reason.as_reason_str(),
                "SV2 broadcast: send_complete"
            ),
            Err(e) => debug!(
                poll = poll_count,
                template_id = snapshot.template_id,
                result = "Err",
                error = ?e,
                refresh_reason = refresh_reason.as_reason_str(),
                "SV2 broadcast: send_complete"
            ),
        }
        match send_result {
            Ok(n) => debug!(
                poll = poll_count,
                receivers = n,
                template_id = snapshot.template_id,
                refresh_reason = refresh_reason.as_reason_str(),
                height = template.height,
                "SV2 broadcast: template update dispatched to subscribed sessions"
            ),
            Err(_) => debug!(
                poll = poll_count,
                "template push channel closed; skip SV2 queue"
            ),
        }
        *last_push_fp = Some(fp);
        *last_broadcast = Some(snapshot.clone());
        snapshot
    } else {
        let template_id = last_broadcast
            .as_ref()
            .expect("broadcast branch implies last_broadcast")
            .template_id;
        TemplateSnapshot {
            template_id,
            template: template.clone(),
        }
    };

    let _ = template_tx.send(Some(snapshot.clone()));
    *previous = Some(snapshot.clone());
}

#[cfg(test)]
mod refresh_tests {
    use super::*;
    use crate::template::TemplateTx;

    fn stub_template(
        prev_hash: &str,
        height: u64,
        txids_and_fees: Vec<(String, u64)>,
    ) -> AzcoinTemplate {
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
            transactions: txids_and_fees
                .into_iter()
                .map(|(tid, fee)| TemplateTx {
                    txid: tid,
                    fee,
                    weight: 0,
                    sigops: 0,
                    data: String::new(),
                })
                .collect(),
        }
    }

    #[test]
    fn identical_template_twice_does_not_broadcast_twice() {
        let prev_h = "0000000000000000000000000000000000000000000000000000000000000001";
        let t = stub_template(prev_h, 1, vec![("a".repeat(64), 1000)]);
        let (push_tx, _) = broadcast::channel::<TemplateUpdatePayload>(16);
        let mut sub = push_tx.subscribe();
        let (watch_tx, _watch_rx) = watch::channel(None);

        let mut previous = None;
        let mut last_seen = None;
        let mut last_broadcast = None;
        let mut last_fp = None;
        let mut next_tid = 1u64;

        ingest_azcoin_template(
            t.clone(),
            TemplateRefreshReason::Poll,
            1,
            5000,
            5000,
            &mut previous,
            &mut last_seen,
            &mut last_broadcast,
            &mut last_fp,
            &mut next_tid,
            &watch_tx,
            &push_tx,
        );
        assert!(sub.try_recv().is_ok(), "initial template broadcasts");

        ingest_azcoin_template(
            t.clone(),
            TemplateRefreshReason::Poll,
            2,
            5000,
            5000,
            &mut previous,
            &mut last_seen,
            &mut last_broadcast,
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

    #[test]
    fn mempool_only_low_fee_delta_suppresses_broadcast() {
        let prev_h = "aa".repeat(32);
        let a = stub_template(prev_h.as_str(), 10, vec![("b".repeat(64), 1000)]);
        let mut b = a.clone();
        b.transactions.push(TemplateTx {
            txid: "c".repeat(64),
            fee: 2000,
            weight: 0,
            sigops: 0,
            data: String::new(),
        });

        let (push_tx, _) = broadcast::channel::<TemplateUpdatePayload>(16);
        let mut sub = push_tx.subscribe();
        let (watch_tx, _) = watch::channel(None);
        let mut previous = None;
        let mut last_seen = None;
        let mut last_broadcast = None;
        let mut last_fp = None;
        let mut next_tid = 1u64;

        ingest_azcoin_template(
            a,
            TemplateRefreshReason::Poll,
            1,
            5000,
            5000,
            &mut previous,
            &mut last_seen,
            &mut last_broadcast,
            &mut last_fp,
            &mut next_tid,
            &watch_tx,
            &push_tx,
        );
        let _ = sub.try_recv().expect("first push");

        ingest_azcoin_template(
            b,
            TemplateRefreshReason::ZmqRawtx,
            2,
            5000,
            5000,
            &mut previous,
            &mut last_seen,
            &mut last_broadcast,
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
            "fee delta 2000 < 5000 must not broadcast"
        );
    }

    #[test]
    fn mempool_only_high_fee_delta_broadcasts() {
        let prev_h = "dd".repeat(32);
        let a = stub_template(prev_h.as_str(), 5, vec![("e".repeat(64), 1000)]);
        let mut b = a.clone();
        b.transactions.push(TemplateTx {
            txid: "f".repeat(64),
            fee: 10_000,
            weight: 0,
            sigops: 0,
            data: String::new(),
        });

        let (push_tx, _) = broadcast::channel::<TemplateUpdatePayload>(16);
        let mut sub = push_tx.subscribe();
        let (watch_tx, _) = watch::channel(None);
        let mut previous = None;
        let mut last_seen = None;
        let mut last_broadcast = None;
        let mut last_fp = None;
        let mut next_tid = 1u64;

        ingest_azcoin_template(
            a,
            TemplateRefreshReason::Poll,
            1,
            5000,
            5000,
            &mut previous,
            &mut last_seen,
            &mut last_broadcast,
            &mut last_fp,
            &mut next_tid,
            &watch_tx,
            &push_tx,
        );
        let _ = sub.try_recv();

        ingest_azcoin_template(
            b,
            TemplateRefreshReason::ZmqSequence,
            2,
            5000,
            5000,
            &mut previous,
            &mut last_seen,
            &mut last_broadcast,
            &mut last_fp,
            &mut next_tid,
            &watch_tx,
            &push_tx,
        );
        assert!(
            sub.try_recv().is_ok(),
            "fee_delta >= threshold should broadcast"
        );
    }

    #[test]
    fn max_template_transactions_suppresses_mempool_broadcast() {
        let prev_h = "11".repeat(32);
        let mut txs_small: Vec<(String, u64)> = Vec::new();
        txs_small.push(("aa".repeat(32), 5000_u64));
        for i in 0..5 {
            txs_small.push((format!("{:064x}", i), 500));
        }
        let base = stub_template(prev_h.as_str(), 99, txs_small);

        let mut too_many = base.clone();
        for i in 0..6000 {
            too_many.transactions.push(TemplateTx {
                txid: format!("bb{:062x}", i),
                fee: 1,
                weight: 0,
                sigops: 0,
                data: String::new(),
            });
        }

        let (push_tx, _) = broadcast::channel::<TemplateUpdatePayload>(16);
        let mut sub = push_tx.subscribe();
        let (watch_tx, _) = watch::channel(None);
        let mut previous = None;
        let mut last_seen = None;
        let mut last_broadcast = None;
        let mut last_fp = None;
        let mut next_tid = 1u64;

        ingest_azcoin_template(
            base,
            TemplateRefreshReason::Poll,
            1,
            5000,
            5000,
            &mut previous,
            &mut last_seen,
            &mut last_broadcast,
            &mut last_fp,
            &mut next_tid,
            &watch_tx,
            &push_tx,
        );
        let _ = sub.try_recv();

        ingest_azcoin_template(
            too_many,
            TemplateRefreshReason::ZmqRawtx,
            2,
            1,
            5000,
            &mut previous,
            &mut last_seen,
            &mut last_broadcast,
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
            "oversized mempool template must not broadcast"
        );
    }

    #[test]
    fn tip_change_broadcasts_despite_low_fee_threshold_path() {
        let h1 = "11".repeat(32);
        let h2 = "22".repeat(32);
        let a = stub_template(h1.as_str(), 1, vec![("cc".repeat(64), 1000)]);
        let b = stub_template(h2.as_str(), 2, vec![("cc".repeat(64), 500)]);

        let (push_tx, _) = broadcast::channel::<TemplateUpdatePayload>(16);
        let mut sub = push_tx.subscribe();
        let (watch_tx, _) = watch::channel(None);
        let mut previous = None;
        let mut last_seen = None;
        let mut last_broadcast = None;
        let mut last_fp = None;
        let mut next_tid = 1u64;

        ingest_azcoin_template(
            a,
            TemplateRefreshReason::Poll,
            1,
            5000,
            5000,
            &mut previous,
            &mut last_seen,
            &mut last_broadcast,
            &mut last_fp,
            &mut next_tid,
            &watch_tx,
            &push_tx,
        );
        let _ = sub.try_recv();

        ingest_azcoin_template(
            b,
            TemplateRefreshReason::ZmqHashblock,
            2,
            5000,
            5000,
            &mut previous,
            &mut last_seen,
            &mut last_broadcast,
            &mut last_fp,
            &mut next_tid,
            &watch_tx,
            &push_tx,
        );
        assert!(sub.try_recv().is_ok(), "new tip must broadcast");
    }

    #[test]
    fn tip_change_broadcasts_above_max_transaction_cap() {
        let h1 = "33".repeat(32);
        let h2 = "44".repeat(32);
        let a = stub_template(h1.as_str(), 10, vec![("dd".repeat(64), 1000)]);
        let mut b = stub_template(h2.as_str(), 11, vec![("dd".repeat(64), 1000)]);
        for i in 0..9000 {
            b.transactions.push(TemplateTx {
                txid: format!("{:064x}", i),
                fee: 1,
                weight: 0,
                sigops: 0,
                data: String::new(),
            });
        }

        let (push_tx, _) = broadcast::channel::<TemplateUpdatePayload>(16);
        let mut sub = push_tx.subscribe();
        let (watch_tx, _) = watch::channel(None);
        let mut previous = None;
        let mut last_seen = None;
        let mut last_broadcast = None;
        let mut last_fp = None;
        let mut next_tid = 1u64;

        ingest_azcoin_template(
            a,
            TemplateRefreshReason::Poll,
            1,
            5000,
            5000,
            &mut previous,
            &mut last_seen,
            &mut last_broadcast,
            &mut last_fp,
            &mut next_tid,
            &watch_tx,
            &push_tx,
        );
        let _ = sub.try_recv();

        ingest_azcoin_template(
            b,
            TemplateRefreshReason::Poll,
            2,
            5000,
            5000,
            &mut previous,
            &mut last_seen,
            &mut last_broadcast,
            &mut last_fp,
            &mut next_tid,
            &watch_tx,
            &push_tx,
        );
        assert!(
            sub.try_recv().is_ok(),
            "tip change ignores max_template_transactions cap",
        );
    }
}
