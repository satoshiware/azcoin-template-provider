//! ZMQ Subscriber thread — interrupt/wakeup hints only (`hashblock`, `sequence` topics).
//! Template construction remains authoritative via RPC `getblocktemplate`.

use std::thread;
use std::time::Duration;

use tokio::sync::mpsc::UnboundedSender;
use tracing::{debug, error, info, trace, warn};

/// Which subscribed topic signaled a wakeup (no payload semantics).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ZmqWakeupKind {
    Hashblock,
    Sequence,
}

/// Owned parameters for [`spawn_zmq_thread`].
#[derive(Clone, Debug)]
pub(crate) struct ZmqThreadConfig {
    pub endpoint: String,
    pub subscribe_hashblock: bool,
    pub subscribe_sequence: bool,
    pub receive_timeout_ms: i32,
    pub reconnect_backoff_ms: u64,
}

pub(crate) fn merge_zmq_pending(
    prior: Option<ZmqWakeupKind>,
    next: ZmqWakeupKind,
) -> ZmqWakeupKind {
    match prior {
        None => next,
        Some(ZmqWakeupKind::Hashblock) => ZmqWakeupKind::Hashblock,
        Some(ZmqWakeupKind::Sequence) => match next {
            ZmqWakeupKind::Hashblock => ZmqWakeupKind::Hashblock,
            ZmqWakeupKind::Sequence => ZmqWakeupKind::Sequence,
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
        endpoint = %cfg.endpoint,
        subscribe_hashblock = cfg.subscribe_hashblock,
        subscribe_sequence = cfg.subscribe_sequence,
        recv_timeout_ms = cfg.receive_timeout_ms,
        reconnect_backoff_ms = cfg.reconnect_backoff_ms,
        "ZMQ subscriber thread starting"
    );

    loop {
        if let Err(e) = subscribe_loop(&cfg, &wakeup_tx) {
            warn!(
                event = "zmq_error",
                error = ?e,
                "ZMQ subscribe loop exited; backing off before reconnect attempt"
            );
            info!(
                event = "zmq_backoff_sleep",
                backoff_ms = cfg.reconnect_backoff_ms,
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
    sock.connect(&cfg.endpoint)?;

    if cfg.subscribe_hashblock {
        sock.set_subscribe(b"hashblock")?;
    }
    if cfg.subscribe_sequence {
        sock.set_subscribe(b"sequence")?;
    }

    info!(
        event = "zmq_subscriber_ready",
        endpoint = %cfg.endpoint,
        subscribe_hashblock = cfg.subscribe_hashblock,
        subscribe_sequence = cfg.subscribe_sequence,
        recv_timeout_ms = cfg.receive_timeout_ms,
        "ZMQ subscriber subscribed (wakeup/interrupt-only; payloads are ignored for template assembly)"
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
                handle_multipart(parts, cfg, wakeup_tx)?;
            }
            Err(zmq::Error::EAGAIN) => {
                // Periodic timeout — keep looping (allows responsive shutdown only at process terminate).
                continue;
            }
            Err(e) => {
                warn!(
                    event = "zmq_error",
                    error = ?e,
                    recv_timeout_ms = cfg.receive_timeout_ms,
                    endpoint = %cfg.endpoint,
                    "recv_multipart failure; restarting subscribe loop after reconnect"
                );
                return Err(anyhow::anyhow!(e));
            }
        }
    }
    #[allow(unreachable_code)]
    Ok(())
}

fn classify_topic(first_part: &[u8], cfg: &ZmqThreadConfig) -> Option<ZmqWakeupKind> {
    if cfg.subscribe_hashblock && first_part == b"hashblock" {
        return Some(ZmqWakeupKind::Hashblock);
    }
    if cfg.subscribe_sequence && first_part == b"sequence" {
        return Some(ZmqWakeupKind::Sequence);
    }
    None
}

fn handle_multipart(
    parts: Vec<Vec<u8>>,
    cfg: &ZmqThreadConfig,
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
        "ZMQ multipart received (topics/payload lengths only; bodies not inspected for template assembly)"
    );

    match classify_topic(first, cfg) {
        Some(k) => {
            if wakeup_tx.send(k).is_err() {
                error!(
                    event = "zmq_error",
                    "ZMQ wakeup channel closed; stopping subscriber forwarding"
                );
                return Err(anyhow::anyhow!("wakeup_tx closed"));
            }
        }
        None => trace!(
            event = "zmq_message_received",
            topic = topic_enc,
            "Frame topic not mapped to wakeup (subscription prefix may still accept other publishers)"
        ),
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_zmq_prioritizes_hashblock_over_sequence() {
        assert_eq!(
            merge_zmq_pending(Some(ZmqWakeupKind::Sequence), ZmqWakeupKind::Hashblock),
            ZmqWakeupKind::Hashblock
        );
        assert_eq!(
            merge_zmq_pending(Some(ZmqWakeupKind::Hashblock), ZmqWakeupKind::Sequence),
            ZmqWakeupKind::Hashblock
        );
        assert_eq!(
            merge_zmq_pending(None, ZmqWakeupKind::Sequence),
            ZmqWakeupKind::Sequence
        );
    }
}
