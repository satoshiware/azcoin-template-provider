//! Template polling loop.
//!
//! Calls `getblocktemplate` every `poll_interval_ms` milliseconds, converts
//! the raw RPC response into an [`AzcoinTemplate`], and compares it to the
//! previous template.  Changes are logged at `INFO`; identical templates are
//! logged at `DEBUG`.
//!
//! The loop is resilient — a single failed RPC call logs an error and retries
//! on the next tick without crashing the service.

use std::time::Duration;

use anyhow::Result;
use tokio::time;
use tracing::{debug, error, info};

use crate::rpc::RpcClient;
use crate::template::AzcoinTemplate;

/// Run the polling loop until the process is terminated.
pub async fn run(client: &RpcClient, poll_interval_ms: u64) -> Result<()> {
    let interval = Duration::from_millis(poll_interval_ms);
    let mut ticker = time::interval(interval);
    let mut previous: Option<AzcoinTemplate> = None;
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

        previous = Some(template);
    }
}
