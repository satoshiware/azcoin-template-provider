//! JSON-RPC 1.0 client for `azcoind`.
//!
//! Wraps [`reqwest`] with Basic-auth and provides typed async methods for each
//! RPC call the template provider needs.  The generic [`call`](RpcClient::call)
//! method handles envelope serialization / deserialization and error mapping so
//! individual wrappers stay one-liners.
//!
//! [`submit_block`](RpcClient::submit_block) is used on the **solved-block path**: after the pool
//! sends SV2 `SubmitSolution`, [`crate::tp_server`] assembles full block bytes and submits them here.
//!
//! # Template request rules
//!
//! By default, `getblocktemplate` sends an empty request object `{}`.  This is
//! intentional — AZCOIN may not support SegWit, and sending
//! `{"rules":["segwit"]}` to a node that does not know about it will fail.
//! Use [`RpcClient::with_template_rules`] (or the `template_rules` config
//! field) to opt in to specific rules when the chain supports them.

use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{anyhow, Context, Result};
use reqwest::Client;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};

use crate::template::{RpcBlockHeader, RpcBlockTemplate, RpcBlockchainInfo};

/// Async JSON-RPC client that talks to a single `azcoind` node.
pub struct RpcClient {
    url: String,
    user: String,
    password: String,
    http: Client,
    next_id: AtomicU64,
    template_rules: Vec<String>,
}

#[derive(Serialize)]
struct JsonRpcRequest<'a> {
    jsonrpc: &'static str,
    id: u64,
    method: &'a str,
    params: &'a [Value],
}

#[derive(Deserialize)]
struct JsonRpcResponse {
    result: Value,
    error: Option<JsonRpcError>,
}

#[derive(Deserialize, Debug)]
struct JsonRpcError {
    code: i64,
    message: String,
}

impl RpcClient {
    pub fn new(url: String, user: String, password: String) -> Self {
        Self {
            url,
            user,
            password,
            http: Client::new(),
            next_id: AtomicU64::new(1),
            template_rules: Vec::new(),
        }
    }

    /// Builder-style setter: attach BIP feature rules that will be included in
    /// every `getblocktemplate` request.  An empty vec (the default) sends
    /// `{}` — safe for chains that do not activate SegWit or other soft forks.
    #[allow(dead_code)]
    pub fn with_template_rules(mut self, rules: Vec<String>) -> Self {
        self.template_rules = rules;
        self
    }

    async fn call<T: DeserializeOwned>(&self, method: &str, params: &[Value]) -> Result<T> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);

        let body = JsonRpcRequest {
            jsonrpc: "1.0",
            id,
            method,
            params,
        };

        let http_resp = self
            .http
            .post(&self.url)
            .basic_auth(&self.user, Some(&self.password))
            .json(&body)
            .send()
            .await
            .with_context(|| format!("HTTP request for RPC method '{}' failed", method))?;

        let status = http_resp.status();
        if !status.is_success() {
            let text = http_resp.text().await.unwrap_or_default();
            return Err(anyhow!(
                "RPC '{}' returned HTTP {}: {}",
                method,
                status,
                text
            ));
        }

        let rpc_resp: JsonRpcResponse = http_resp
            .json()
            .await
            .with_context(|| format!("failed to deserialize JSON-RPC envelope for '{}'", method))?;

        if let Some(e) = rpc_resp.error {
            return Err(anyhow!(
                "RPC '{}' error [{}]: {}",
                method,
                e.code,
                e.message
            ));
        }

        serde_json::from_value(rpc_resp.result)
            .with_context(|| format!("failed to deserialize result for RPC '{}'", method))
    }

    // ---- public RPC wrappers ------------------------------------------------

    /// Return chain metadata: height, headers, best hash, IBD status, etc.
    pub async fn get_blockchain_info(&self) -> Result<RpcBlockchainInfo> {
        self.call("getblockchaininfo", &[]).await
    }

    /// Fetch a block template from the node.  The `rules` array sent in the
    /// template request is controlled by [`RpcClient::with_template_rules`].  When empty
    /// (the default), an empty object `{}` is sent — compatible with AZCOIN
    /// nodes that have no SegWit soft fork.
    pub async fn get_block_template(&self) -> Result<RpcBlockTemplate> {
        let request = if self.template_rules.is_empty() {
            json!({})
        } else {
            json!({ "rules": self.template_rules })
        };
        self.call("getblocktemplate", &[request]).await
    }

    /// Submit a fully-serialised block.  Returns `None` on acceptance or
    /// `Some(reason)` on rejection.
    pub async fn submit_block(&self, block_hex: &str) -> Result<Option<String>> {
        self.call("submitblock", &[json!(block_hex)]).await
    }

    /// Return the hash of the current chain tip.
    #[allow(dead_code)]
    pub async fn get_best_block_hash(&self) -> Result<String> {
        self.call("getbestblockhash", &[]).await
    }

    /// Return the verbose header for a given block hash.
    #[allow(dead_code)]
    pub async fn get_block_header(&self, block_hash: &str) -> Result<RpcBlockHeader> {
        self.call("getblockheader", &[json!(block_hash), json!(true)])
            .await
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    #[test]
    fn submitblock_null_result_means_accepted() {
        let result: Option<String> = serde_json::from_value(Value::Null).unwrap();
        assert!(result.is_none(), "null should deserialize to None (accepted)");
    }

    #[test]
    fn submitblock_string_result_means_rejected() {
        let result: Option<String> = serde_json::from_value(json!("duplicate")).unwrap();
        assert_eq!(result.unwrap(), "duplicate");
    }

    #[test]
    fn submitblock_inconclusive_result() {
        let result: Option<String> = serde_json::from_value(json!("inconclusive")).unwrap();
        assert_eq!(result.unwrap(), "inconclusive");
    }

    #[test]
    fn submitblock_high_hash_result() {
        let result: Option<String> = serde_json::from_value(json!("high-hash")).unwrap();
        assert_eq!(result.unwrap(), "high-hash");
    }
}
