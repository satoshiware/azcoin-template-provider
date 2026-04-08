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
use tracing::{info, warn};

use crate::config::Config;
use crate::rpc::RpcClient;

/// Verify RPC connectivity and validate chain/network agreement.
pub async fn check_rpc_connectivity(client: &RpcClient, config: &Config) -> Result<()> {
    info!(url = %config.rpc_url, "Connecting to azcoind");

    let info = client.get_blockchain_info().await?;

    info!(
        chain       = %info.chain,
        blocks      = info.blocks,
        headers     = info.headers,
        best_hash   = %info.bestblockhash,
        ibd         = info.initialblockdownload,
        sync        = format_args!("{:.4}%", info.verificationprogress * 100.0),
        "RPC connection established"
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
        network = %config.network,
        template_rules = ?config.template_rules,
        "Health check passed"
    );

    Ok(())
}
