//! SV2 Template Provider stub — TCP listener with connection lifecycle logging.
//!
//! This is the minimum viable TP server: it binds a TCP socket, accepts
//! connections, and logs open / close / error events.  It holds a
//! [`watch::Receiver`] carrying the latest [`AzcoinTemplate`] so that future
//! phases can push `NewTemplate` messages to connected pools.
//!
//! **Not yet implemented** (explicit non-goals for this stub):
//! - SV2 Noise handshake / encryption
//! - SV2 message framing (`SetupConnection`, `NewTemplate`, etc.)
//! - Solved-block submission relay
//! - Translator proxy integration

use std::net::SocketAddr;

use anyhow::Result;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

use crate::template::AzcoinTemplate;

/// Bind a TCP listener and accept connections in a loop.
///
/// Each accepted connection is handled in its own spawned task.  The
/// `template_rx` receiver is cloned per-connection so every handler can
/// independently read the latest template when needed.
pub async fn run(
    listen_addr: &str,
    template_rx: watch::Receiver<Option<AzcoinTemplate>>,
) -> Result<()> {
    let listener = TcpListener::bind(listen_addr).await?;
    let local_addr = listener.local_addr()?;

    info!(address = %local_addr, "SV2 Template Provider stub listening");

    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                info!(peer = %peer, "SV2 client connected");
                let rx = template_rx.clone();
                tokio::spawn(handle_connection(stream, peer, rx));
            }
            Err(e) => {
                error!("Failed to accept SV2 connection: {}", e);
            }
        }
    }
}

/// Read from a connected client until it disconnects or an error occurs.
///
/// In this stub phase the incoming bytes are counted but not parsed.
/// A future phase will layer SV2 Noise negotiation and message framing here.
async fn handle_connection(
    mut stream: TcpStream,
    peer: SocketAddr,
    _template_rx: watch::Receiver<Option<AzcoinTemplate>>,
) {
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) => {
                info!(peer = %peer, "SV2 client disconnected");
                return;
            }
            Ok(n) => {
                debug!(
                    peer = %peer,
                    bytes = n,
                    "Received data (stub — not processed)"
                );
            }
            Err(e) => {
                warn!(peer = %peer, "SV2 connection error: {}", e);
                return;
            }
        }
    }
}
