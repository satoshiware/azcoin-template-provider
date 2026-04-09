//! Block template types and change-detection logic.
//!
//! This module defines two layers of types:
//!
//! 1. **`Rpc*` structs** — raw JSON-RPC response shapes that mirror exactly
//!    what `azcoind` returns.  Fields that may be absent on AZCOIN (e.g.
//!    `weightlimit`, `default_witness_commitment`) are marked
//!    `#[serde(default)]` so deserialization never fails for those.
//!
//! 2. **[`AzcoinTemplate`]** — a normalized, chain-agnostic internal struct
//!    built from the RPC data via [`AzcoinTemplate::from_rpc`].  The poller
//!    compares successive instances of this type to detect meaningful template
//!    changes while ignoring noise like `curtime` drift.

#![allow(dead_code)]

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash as StdHash, Hasher};

use anyhow::{Context, Result};
use bitcoin::blockdata::block::TxMerkleNode;
use bitcoin::consensus::deserialize;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::{sha256d, Hash as BtcHash};
use bitcoin::Transaction;
use serde::Deserialize;

// ---------------------------------------------------------------------------
// Raw RPC response types
// ---------------------------------------------------------------------------

/// Response from `getblockchaininfo`.
#[derive(Debug, Deserialize)]
pub struct RpcBlockchainInfo {
    pub chain: String,
    pub blocks: u64,
    pub headers: u64,
    pub bestblockhash: String,
    #[serde(default)]
    pub difficulty: f64,
    #[serde(default)]
    pub mediantime: u64,
    #[serde(default)]
    pub verificationprogress: f64,
    #[serde(default)]
    pub initialblockdownload: bool,
}

/// Response from `getblocktemplate`.
///
/// All SegWit-specific and version-bits fields are optional (`#[serde(default)]`)
/// so this struct works for AZCOIN nodes that pre-date or omit those features.
#[derive(Debug, Deserialize)]
pub struct RpcBlockTemplate {
    pub version: u32,
    #[serde(default)]
    pub rules: Vec<String>,
    #[serde(default)]
    pub vbavailable: serde_json::Value,
    #[serde(default)]
    pub vbrequired: u32,
    pub previousblockhash: String,
    pub transactions: Vec<RpcBlockTemplateTx>,
    #[serde(default)]
    pub coinbaseaux: serde_json::Value,
    pub coinbasevalue: u64,
    #[serde(default)]
    pub longpollid: Option<String>,
    pub target: String,
    pub mintime: u64,
    #[serde(default)]
    pub mutable: Vec<String>,
    #[serde(default)]
    pub noncerange: Option<String>,
    #[serde(default)]
    pub sigoplimit: u64,
    #[serde(default)]
    pub sizelimit: u64,
    #[serde(default)]
    pub weightlimit: u64,
    pub curtime: u64,
    pub bits: String,
    pub height: u64,
    #[serde(default)]
    pub default_witness_commitment: Option<String>,
}

/// A single transaction inside a `getblocktemplate` response.
///
/// `hash` (the witness-aware txid) is optional because AZCOIN may not have
/// SegWit.  When absent, `txid` and `hash` are equivalent.
#[derive(Debug, Deserialize)]
pub struct RpcBlockTemplateTx {
    pub data: String,
    pub txid: String,
    #[serde(default)]
    pub hash: Option<String>,
    #[serde(default)]
    pub depends: Vec<u64>,
    pub fee: u64,
    #[serde(default)]
    pub sigops: u64,
    #[serde(default)]
    pub weight: u64,
}

/// Verbose response from `getblockheader <hash> true`.
#[derive(Debug, Deserialize)]
pub struct RpcBlockHeader {
    pub hash: String,
    pub confirmations: i64,
    pub height: u64,
    pub version: u32,
    #[serde(rename = "versionHex", default)]
    pub version_hex: Option<String>,
    pub merkleroot: String,
    pub time: u64,
    pub mediantime: u64,
    pub nonce: u64,
    pub bits: String,
    pub difficulty: f64,
    pub chainwork: String,
    #[serde(rename = "nTx", default)]
    pub n_tx: u64,
    #[serde(default)]
    pub previousblockhash: Option<String>,
    #[serde(default)]
    pub nextblockhash: Option<String>,
}

// ---------------------------------------------------------------------------
// Normalized internal representation — decoupled from the wire format.
// ---------------------------------------------------------------------------

/// Latest template snapshot for live SV2 pushes (built from polled [`AzcoinTemplate`]).
#[derive(Clone, Debug)]
pub struct TemplateUpdatePayload {
    pub template: AzcoinTemplate,
}

/// Fingerprint for deduplicating SV2 template pushes across polls.
///
/// Covers tip identity, difficulty (`bits` / `target`), coinbase value, and non-coinbase tx
/// order/ids. **`curtime` is intentionally omitted** — it advances almost every poll and does not
/// represent a new block-building job for the pool.
pub fn template_push_fingerprint(t: &AzcoinTemplate) -> u64 {
    let mut h = DefaultHasher::new();
    StdHash::hash(&t.previous_block_hash, &mut h);
    StdHash::hash(&t.height, &mut h);
    StdHash::hash(&t.bits, &mut h);
    StdHash::hash(&t.target, &mut h);
    StdHash::hash(&t.coinbase_value, &mut h);
    for tx in &t.transactions {
        StdHash::hash(&tx.txid, &mut h);
    }
    h.finish()
}

/// Chain-agnostic snapshot of a block template.
///
/// Built from [`RpcBlockTemplate`] via [`from_rpc`](Self::from_rpc).
/// The poller stores the most recent instance and uses
/// [`describe_change`](Self::describe_change) to detect meaningful updates.
#[derive(Debug, Clone)]
pub struct AzcoinTemplate {
    pub height: u64,
    pub version: u32,
    pub previous_block_hash: String,
    pub bits: String,
    pub target: String,
    pub curtime: u64,
    pub mintime: u64,
    pub coinbase_value: u64,
    pub size_limit: u64,
    pub weight_limit: u64,
    pub sigop_limit: u64,
    pub default_witness_commitment: Option<String>,
    pub transactions: Vec<TemplateTx>,
}

/// Lightweight per-transaction summary kept inside [`AzcoinTemplate`].
///
/// Only fields needed for change detection and logging are retained;
/// the full raw transaction hex (`data`) is intentionally dropped.
#[derive(Debug, Clone)]
pub struct TemplateTx {
    pub txid: String,
    pub fee: u64,
    pub weight: u64,
    pub sigops: u64,
    /// Full transaction hex from `getblocktemplate` (`data` field), for SV2 merkle paths.
    pub data: String,
}

impl AzcoinTemplate {
    /// Convert a raw RPC response into a normalized template.
    pub fn from_rpc(rpc: &RpcBlockTemplate) -> Self {
        let transactions = rpc
            .transactions
            .iter()
            .map(|tx| TemplateTx {
                txid: tx.txid.clone(),
                fee: tx.fee,
                weight: tx.weight,
                sigops: tx.sigops,
                data: tx.data.clone(),
            })
            .collect();

        Self {
            height: rpc.height,
            version: rpc.version,
            previous_block_hash: rpc.previousblockhash.clone(),
            bits: rpc.bits.clone(),
            target: rpc.target.clone(),
            curtime: rpc.curtime,
            mintime: rpc.mintime,
            coinbase_value: rpc.coinbasevalue,
            size_limit: rpc.sizelimit,
            weight_limit: rpc.weightlimit,
            sigop_limit: rpc.sigoplimit,
            default_witness_commitment: rpc.default_witness_commitment.clone(),
            transactions,
        }
    }

    /// Sum of all transaction fees in satoshis.
    pub fn total_fees(&self) -> u64 {
        self.transactions.iter().map(|tx| tx.fee).sum()
    }

    /// Sum of all transaction weights (zero if weight is not reported).
    pub fn total_weight(&self) -> u64 {
        self.transactions.iter().map(|tx| tx.weight).sum()
    }

    /// Compare two templates and return a human-readable description of what
    /// changed.  Returns `None` when nothing meaningful differs (`curtime`
    /// changes alone are ignored).
    pub fn describe_change(&self, previous: &AzcoinTemplate) -> Option<String> {
        if self.previous_block_hash != previous.previous_block_hash {
            let h = &self.previous_block_hash;
            return Some(format!(
                "new block: height {} -> {}, prev_hash {}..{}",
                previous.height,
                self.height,
                &h[..8.min(h.len())],
                &h[h.len().saturating_sub(8)..],
            ));
        }

        let prev_txids: Vec<&str> = previous.transactions.iter().map(|t| t.txid.as_str()).collect();
        let curr_txids: Vec<&str> = self.transactions.iter().map(|t| t.txid.as_str()).collect();

        if prev_txids != curr_txids || self.coinbase_value != previous.coinbase_value {
            return Some(format!(
                "template updated (height {}): txs {} -> {}, fees {} -> {}, coinbase {} -> {}",
                self.height,
                previous.transactions.len(),
                self.transactions.len(),
                previous.total_fees(),
                self.total_fees(),
                previous.coinbase_value,
                self.coinbase_value,
            ));
        }

        None
    }

    /// Merkle path for SV2 `NewTemplate` (coinbase at index 0, non-coinbase leaves from
    /// `transactions[].data` hex).
    pub fn sv2_merkle_path_hashes(&self) -> Result<Vec<[u8; 32]>> {
        let hexes: Vec<&str> = self.transactions.iter().map(|t| t.data.as_str()).collect();
        merkle_path_from_template_tx_hexes(&hexes)
    }
}

// ---------------------------------------------------------------------------
// SV2 / Bitcoin helpers (Template Distribution `NewTemplate` / `SetNewPrevHash`)
// ---------------------------------------------------------------------------

/// Tx merkle leaf hash (legacy txid) for a `getblocktemplate` transaction `data` hex.
pub fn tx_merkle_leaf_from_hex(tx_hex: &str) -> Result<[u8; 32]> {
    let raw = hex::decode(tx_hex.trim()).context("decode transaction hex")?;
    match deserialize::<Transaction>(&raw) {
        Ok(tx) => Ok(tx.compute_txid().to_byte_array()),
        Err(_) => Ok(<sha256d::Hash as BtcHash>::hash(raw.as_slice()).to_byte_array()),
    }
}

fn pair_merkle(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    let mut eng = TxMerkleNode::engine();
    TxMerkleNode::from_byte_array(a)
        .consensus_encode(&mut eng)
        .expect("in-memory encode");
    TxMerkleNode::from_byte_array(b)
        .consensus_encode(&mut eng)
        .expect("in-memory encode");
    TxMerkleNode::from_engine(eng).to_byte_array()
}

/// Branch hashes for a block where the coinbase is the leftmost leaf and `tx_leaves` are the
/// remaining transaction txids (post-coinbase order), matching Bitcoin’s merkle tree.
pub fn merkle_path_for_coinbase_prefix(tx_leaves: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut leaves: Vec<[u8; 32]> = std::iter::once([0u8; 32])
        .chain(tx_leaves.iter().copied())
        .collect();
    let mut idx = 0usize;
    let mut branch = Vec::new();
    while leaves.len() > 1 {
        if leaves.len() % 2 == 1 {
            leaves.push(*leaves.last().unwrap());
        }
        branch.push(leaves[idx ^ 1]);
        let mut next = Vec::with_capacity(leaves.len() / 2);
        for i in (0..leaves.len()).step_by(2) {
            next.push(pair_merkle(leaves[i], leaves[i + 1]));
        }
        idx /= 2;
        leaves = next;
    }
    branch
}

pub fn merkle_path_from_template_tx_hexes(tx_hexes: &[&str]) -> Result<Vec<[u8; 32]>> {
    let mut leaves = Vec::with_capacity(tx_hexes.len());
    for h in tx_hexes {
        if h.is_empty() {
            anyhow::bail!("transaction data hex is empty (cannot build merkle path)");
        }
        leaves.push(tx_merkle_leaf_from_hex(h)?);
    }
    Ok(merkle_path_for_coinbase_prefix(&leaves))
}

/// `nBits` field as a `u32` (same interpretation as Bitcoin header / `getblocktemplate` hex string).
pub fn n_bits_from_bits_hex(bits: &str) -> Result<u32> {
    let s = bits.trim().trim_start_matches("0x");
    u32::from_str_radix(s, 16).context("parse bits hex")
}

/// 32-byte block target from `getblocktemplate` `target` hex (64 hex chars).
pub fn target_bytes_from_hex(target: &str) -> Result<[u8; 32]> {
    let v = hex::decode(target.trim()).context("decode target hex")?;
    anyhow::ensure!(v.len() == 32, "target must be 32 bytes, got {}", v.len());
    Ok(v.try_into().expect("length checked"))
}

/// Previous block hash bytes in **block header** order from RPC hex (reverse of JSON byte order).
pub fn prev_hash_bytes_from_rpc_hex(prev: &str) -> Result<[u8; 32]> {
    let mut v = hex::decode(prev.trim()).context("decode previousblockhash hex")?;
    anyhow::ensure!(v.len() == 32, "prev hash must be 32 bytes, got {}", v.len());
    v.reverse();
    Ok(v.try_into().expect("length checked"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn load_fixture() -> RpcBlockTemplate {
        let json = include_str!("../testdata/getblocktemplate_regtest.json");
        serde_json::from_str(json).expect("fixture must deserialize")
    }

    // -- deserialization ------------------------------------------------------

    #[test]
    fn parse_azcoin_fixture() {
        let tpl = load_fixture();
        assert_eq!(tpl.height, 201);
        assert_eq!(tpl.version, 536870912);
        assert_eq!(
            tpl.previousblockhash,
            "7e4bac9158349c6370c2b32d046cc52149b0ea47cdd6e47e83d9e0f87e2456a1"
        );
        assert_eq!(tpl.bits, "207fffff");
        assert_eq!(tpl.coinbasevalue, 5_000_037_500);
        assert_eq!(tpl.transactions.len(), 2);
        assert!(
            tpl.default_witness_commitment.is_none(),
            "AZCOIN fixture should have no witness commitment"
        );
    }

    #[test]
    fn parse_fixture_transactions() {
        let tpl = load_fixture();
        let tx0 = &tpl.transactions[0];
        assert_eq!(
            tx0.txid,
            "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"
        );
        assert_eq!(tx0.fee, 22_500);
        assert_eq!(tx0.sigops, 1);
        assert_eq!(tx0.weight, 900);
        assert!(tx0.depends.is_empty());
    }

    #[test]
    fn parse_fixture_without_witness_fields() {
        let json = r#"{
            "version": 536870912,
            "previousblockhash": "00000000000000000000aabbccdd",
            "transactions": [],
            "coinbasevalue": 5000000000,
            "target": "00000000ffff0000000000000000000000000000000000000000000000000000",
            "mintime": 1700000000,
            "curtime": 1700000100,
            "bits": "1d00ffff",
            "height": 100
        }"#;
        let tpl: RpcBlockTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tpl.height, 100);
        assert!(tpl.rules.is_empty());
        assert!(tpl.default_witness_commitment.is_none());
        assert_eq!(tpl.weightlimit, 0, "missing weightlimit should default to 0");
        assert_eq!(tpl.sigoplimit, 0);
        assert_eq!(tpl.sizelimit, 0);
    }

    // -- from_rpc conversion --------------------------------------------------

    #[test]
    fn from_rpc_preserves_all_fields() {
        let rpc = load_fixture();
        let tpl = AzcoinTemplate::from_rpc(&rpc);

        assert_eq!(tpl.height, 201);
        assert_eq!(tpl.version, 536870912);
        assert_eq!(tpl.previous_block_hash, rpc.previousblockhash);
        assert_eq!(tpl.bits, "207fffff");
        assert_eq!(tpl.coinbase_value, 5_000_037_500);
        assert_eq!(tpl.transactions.len(), 2);
        assert_eq!(tpl.total_fees(), 22_500 + 15_000);
        assert_eq!(tpl.total_weight(), 900 + 1200);
        assert!(tpl.default_witness_commitment.is_none());
    }

    // -- change detection -----------------------------------------------------

    fn make_template(
        height: u64,
        prev_hash: &str,
        coinbase_value: u64,
        txids: &[&str],
    ) -> AzcoinTemplate {
        AzcoinTemplate {
            height,
            version: 536870912,
            previous_block_hash: prev_hash.to_string(),
            bits: "207fffff".into(),
            target: "7fffff00".into(),
            curtime: 1_700_000_100,
            mintime: 1_700_000_000,
            coinbase_value,
            size_limit: 4_000_000,
            weight_limit: 4_000_000,
            sigop_limit: 80_000,
            default_witness_commitment: None,
            transactions: txids
                .iter()
                .map(|id| TemplateTx {
                    txid: id.to_string(),
                    fee: 10_000,
                    weight: 500,
                    sigops: 1,
                    data: String::new(),
                })
                .collect(),
        }
    }

    #[test]
    fn detect_new_block() {
        let prev = make_template(200, "aaaa0000bbbb1111cccc2222dddd3333eeee4444ffff5555aaaa0000bbbb1111", 5_000_000_000, &["tx1"]);
        let curr = make_template(201, "bbbb1111cccc2222dddd3333eeee4444ffff5555aaaa0000bbbb1111cccc2222", 5_000_000_000, &["tx1"]);

        let msg = curr.describe_change(&prev).expect("should detect change");
        assert!(msg.contains("new block"), "expected 'new block', got: {msg}");
        assert!(msg.contains("200"), "should mention old height");
        assert!(msg.contains("201"), "should mention new height");
    }

    #[test]
    fn detect_template_update_tx_change() {
        let hash = "aaaa0000bbbb1111cccc2222dddd3333eeee4444ffff5555aaaa0000bbbb1111";
        let prev = make_template(200, hash, 5_000_010_000, &["tx1"]);
        let curr = make_template(200, hash, 5_000_020_000, &["tx1", "tx2"]);

        let msg = curr.describe_change(&prev).expect("should detect change");
        assert!(msg.contains("template updated"), "expected 'template updated', got: {msg}");
        assert!(msg.contains("txs 1 -> 2"), "should show tx count change, got: {msg}");
    }

    #[test]
    fn detect_template_update_coinbase_only() {
        let hash = "aaaa0000bbbb1111cccc2222dddd3333eeee4444ffff5555aaaa0000bbbb1111";
        let prev = make_template(200, hash, 5_000_000_000, &["tx1"]);
        let curr = make_template(200, hash, 5_000_010_000, &["tx1"]);

        let msg = curr.describe_change(&prev).expect("should detect change");
        assert!(msg.contains("template updated"), "got: {msg}");
        assert!(msg.contains("coinbase"), "should mention coinbase change");
    }

    #[test]
    fn no_change_when_only_curtime_differs() {
        let hash = "aaaa0000bbbb1111cccc2222dddd3333eeee4444ffff5555aaaa0000bbbb1111";
        let prev = make_template(200, hash, 5_000_000_000, &["tx1"]);
        let mut curr = make_template(200, hash, 5_000_000_000, &["tx1"]);
        curr.curtime += 1;

        assert!(
            curr.describe_change(&prev).is_none(),
            "curtime-only change should be ignored"
        );
    }

    #[test]
    fn no_change_when_identical() {
        let hash = "aaaa0000bbbb1111cccc2222dddd3333eeee4444ffff5555aaaa0000bbbb1111";
        let a = make_template(200, hash, 5_000_000_000, &["tx1"]);
        let b = make_template(200, hash, 5_000_000_000, &["tx1"]);
        assert!(a.describe_change(&b).is_none());
    }
}
