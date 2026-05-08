//! ZMQ Subscriber thread — interrupt/wakeup hints only (`rawtx`, `hashblock`,
//! `sequence` topics).
//! Template construction remains authoritative via RPC `getblocktemplate`.

use std::thread;
use std::time::Duration;

use tokio::sync::mpsc::UnboundedSender;
use tracing::{debug, error, info, trace, warn};

/// Which subscribed topic signaled a wakeup (no payload semantics).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ZmqWakeupKind {
    /// Mempool / transaction ingress hint.
    Rawtx,
    Hashblock,
    /// Block-chain or mempool ordering hint (`sequence` publishes both).
    Sequence,
}

/// Owned parameters for [`spawn_zmq_thread`].
#[derive(Clone, Debug)]
pub(crate) struct ZmqThreadConfig {
    pub endpoint_rawtx: String,
    pub endpoint_hashblock: String,
    pub endpoint_sequence: String,
    pub receive_timeout_ms: i32,
    pub reconnect_backoff_ms: u64,
}

/// Merge debounced wakes: **`hashblock` wins over `sequence` and `rawtx`**; otherwise
/// the latest mempool-class topic replaces the prior one.
pub(crate) fn merge_zmq_pending(
    prior: Option<ZmqWakeupKind>,
    next: ZmqWakeupKind,
) -> ZmqWakeupKind {
    match next {
        ZmqWakeupKind::Hashblock => ZmqWakeupKind::Hashblock,
        _ => match prior {
            Some(ZmqWakeupKind::Hashblock) => ZmqWakeupKind::Hashblock,
            None => next,
            Some(_) => next,
        },
    }
}

pub(crate) fn topic_label_for_event(first_part: &[u8]) -> &'static str {
    if std::str::from_utf8(first_part).is_ok() {
        "utf8_topic"
    } else {
        "non_utf8_topic"
    }
}

/// Map the first multipart frame (topic string) to a wakeup kind (`None` when unknown).
pub(crate) fn classify_zmq_topic(first_part: &[u8]) -> Option<ZmqWakeupKind> {
    match first_part {
        b"rawtx" => Some(ZmqWakeupKind::Rawtx),
        b"hashblock" => Some(ZmqWakeupKind::Hashblock),
        b"sequence" => Some(ZmqWakeupKind::Sequence),
        _ => None,
    }
}

/// Runs until process exit or unrecoverable wakeup channel closure after successful send failures.
pub(crate) fn spawn_zmq_thread(
    cfg: ZmqThreadConfig,
    wakeup_tx: UnboundedSender<ZmqWakeupKind>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || zmq_runner(cfg, wakeup_tx))
}

fn zmq_runner(cfg: ZmqThreadConfig, wakeup_tx: UnboundedSender<ZmqWakeupKind>) {
    info!(
        event = "zmq_subscriber_starting",
        endpoint_rawtx = %cfg.endpoint_rawtx,
        endpoint_hashblock = %cfg.endpoint_hashblock,
        endpoint_sequence = %cfg.endpoint_sequence,
        recv_timeout_ms = cfg.receive_timeout_ms,
        reconnect_backoff_ms = cfg.reconnect_backoff_ms,
        "ZMQ subscriber thread starting (rawtx/hashblock/sequence; payloads ignored for templates)"
    );

    loop {
        if let Err(e) = subscribe_loop(&cfg, &wakeup_tx) {
            warn!(
                event = "zmq_error",
                polling_fallback_active = true,
                error = ?e,
                endpoint_rawtx = %cfg.endpoint_rawtx,
                endpoint_hashblock = %cfg.endpoint_hashblock,
                endpoint_sequence = %cfg.endpoint_sequence,
                reconnect_backoff_ms = cfg.reconnect_backoff_ms,
                "ZMQ subscribe loop exited; poll_interval_ms remains active — backing off before reconnect"
            );
            info!(
                event = "zmq_backoff_sleep",
                backoff_ms = cfg.reconnect_backoff_ms,
                polling_fallback_active = true,
                "attempting reconnect after backoff delay"
            );
            thread::sleep(Duration::from_millis(cfg.reconnect_backoff_ms));
        }
    }
}

fn subscribe_loop(
    cfg: &ZmqThreadConfig,
    wakeup_tx: &UnboundedSender<ZmqWakeupKind>,
) -> Result<(), anyhow::Error> {
    let ctx = zmq::Context::new();
    let sock = ctx.socket(zmq::SUB)?;
    sock.set_rcvtimeo(cfg.receive_timeout_ms)?;
    sock.connect(&cfg.endpoint_rawtx)?;
    sock.connect(&cfg.endpoint_hashblock)?;
    sock.connect(&cfg.endpoint_sequence)?;
    sock.set_subscribe(b"rawtx")?;
    sock.set_subscribe(b"hashblock")?;
    sock.set_subscribe(b"sequence")?;

    info!(
        event = "zmq_subscriber_ready",
        endpoint_rawtx = %cfg.endpoint_rawtx,
        endpoint_hashblock = %cfg.endpoint_hashblock,
        endpoint_sequence = %cfg.endpoint_sequence,
        recv_timeout_ms = cfg.receive_timeout_ms,
        "ZMQ subscriber connected and subscribed (wakeup-only; templates from getblocktemplate only)"
    );

    loop {
        match sock.recv_multipart(0) {
            Ok(parts) if parts.is_empty() => {
                trace!(
                    event = "zmq_message_received",
                    topic = "_empty_parts",
                    payload_len = 0,
                    "ZMQ multipart had no frames; ignoring"
                );
            }
            Ok(parts) => {
                handle_multipart(parts, wakeup_tx)?;
            }
            Err(zmq::Error::EAGAIN) => {
                continue;
            }
            Err(e) => {
                warn!(
                    event = "zmq_error",
                    polling_fallback_active = true,
                    error = ?e,
                    recv_timeout_ms = cfg.receive_timeout_ms,
                    endpoint_rawtx = %cfg.endpoint_rawtx,
                    endpoint_hashblock = %cfg.endpoint_hashblock,
                    endpoint_sequence = %cfg.endpoint_sequence,
                    "recv_multipart failure; restarting subscribe loop after reconnect"
                );
                return Err(anyhow::anyhow!(e));
            }
        }
    }
    #[allow(unreachable_code)]
    Ok(())
}

fn handle_multipart(
    parts: Vec<Vec<u8>>,
    wakeup_tx: &UnboundedSender<ZmqWakeupKind>,
) -> Result<(), anyhow::Error> {
    debug_assert!(!parts.is_empty());
    let first = parts[0].as_slice();
    let topic_enc = topic_label_for_event(first);
    let payload_len: usize = parts.iter().skip(1).map(|p| p.len()).sum();

    debug!(
        event = "zmq_message_received",
        topic = topic_enc,
        topic_frame_len = first.len(),
        payload_len,
        multipart_frames = parts.len(),
        "ZMQ multipart received (topic frame length only — bodies never parsed for templates)"
    );

    match classify_zmq_topic(first) {
        Some(k) => {
            if wakeup_tx.send(k).is_err() {
                error!(
                    event = "zmq_error",
                    polling_fallback_active = true,
                    "ZMQ wakeup channel closed; stopping subscriber forwarding"
                );
                return Err(anyhow::anyhow!("wakeup_tx closed"));
            }
        }
        None => trace!(
            event = "zmq_message_received",
            topic = topic_enc,
            "Frame topic not mapped to wakeup (unexpected publisher framing)"
        ),
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_zmq_prioritizes_hashblock_over_other_topics() {
        assert_eq!(
            merge_zmq_pending(Some(ZmqWakeupKind::Sequence), ZmqWakeupKind::Hashblock),
            ZmqWakeupKind::Hashblock
        );
        assert_eq!(
            merge_zmq_pending(Some(ZmqWakeupKind::Hashblock), ZmqWakeupKind::Sequence),
            ZmqWakeupKind::Hashblock
        );
        assert_eq!(
            merge_zmq_pending(Some(ZmqWakeupKind::Rawtx), ZmqWakeupKind::Hashblock),
            ZmqWakeupKind::Hashblock
        );
        assert_eq!(
            merge_zmq_pending(Some(ZmqWakeupKind::Hashblock), ZmqWakeupKind::Rawtx),
            ZmqWakeupKind::Hashblock
        );
    }

    #[test]
    fn merge_non_hashblock_last_topic_wins() {
        assert_eq!(
            merge_zmq_pending(Some(ZmqWakeupKind::Rawtx), ZmqWakeupKind::Sequence),
            ZmqWakeupKind::Sequence
        );
        assert_eq!(
            merge_zmq_pending(Some(ZmqWakeupKind::Sequence), ZmqWakeupKind::Rawtx),
            ZmqWakeupKind::Rawtx
        );
    }

    #[test]
    fn classify_topics() {
        assert_eq!(classify_zmq_topic(b"rawtx"), Some(ZmqWakeupKind::Rawtx));
        assert_eq!(
            classify_zmq_topic(b"hashblock"),
            Some(ZmqWakeupKind::Hashblock)
        );
        assert_eq!(
            classify_zmq_topic(b"sequence"),
            Some(ZmqWakeupKind::Sequence)
        );
        assert_eq!(classify_zmq_topic(b"other"), None);
    }
}
