//! Startup health check.
//!
//! Called once before the polling loop begins.  Verifies that:
//!
//! 1. `azcoind` is reachable over JSON-RPC.
//! 2. The node's reported chain name matches the configured `network`.
//! 3. The node is not still in initial block download (warning only).
//!
//! If any hard check fails, the service exits with a clear error message
//! rather than silently polling a misconfigured node.

use anyhow::{bail, Result};
use tracing::{debug, info, warn};

use crate::config::Config;
use crate::rpc::RpcClient;

/// Verify RPC connectivity and validate chain/network agreement.
pub async fn check_rpc_connectivity(client: &RpcClient, config: &Config) -> Result<()> {
    debug!(url = %config.rpc_url, "Calling getblockchaininfo for startup check");

    let info = client.get_blockchain_info().await?;

    debug!(
        chain       = %info.chain,
        blocks      = info.blocks,
        headers     = info.headers,
        best_hash   = %info.bestblockhash,
        ibd         = info.initialblockdownload,
        sync        = format_args!("{:.4}%", info.verificationprogress * 100.0),
        "getblockchaininfo response"
    );

    if info.chain != config.network {
        bail!(
            "network mismatch: config expects '{}' but azcoind reports '{}'",
            config.network,
            info.chain
        );
    }

    if info.initialblockdownload {
        warn!("Node is still performing initial block download — getblocktemplate may fail");
    }

    info!(
        event = "rpc_connectivity_ready",
        network = %config.network,
        template_rules = ?config.template_rules,
        "Startup JSON-RPC connectivity and chain name validated"
    );

    Ok(())
}
