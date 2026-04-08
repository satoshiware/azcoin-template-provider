//! TOML configuration loading for the azcoin-template-provider service.
//!
//! The config file is the single source of truth for all runtime settings:
//! RPC connection details, polling interval, target network, and optional
//! template request rules.  See `config/azcoin-template-provider.toml.example`
//! for a fully-commented reference.

use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

/// Top-level configuration, deserialized from a TOML file.
///
/// Every field except `template_rules` is required.  `template_rules` defaults
/// to an empty list when omitted, which tells `getblocktemplate` to make no
/// assumptions about soft-fork features (safe for AZCOIN).
#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    /// JSON-RPC endpoint of `azcoind`, e.g. `http://127.0.0.1:8332`.
    pub rpc_url: String,
    /// RPC username (must match `-rpcuser` on the node).
    pub rpc_user: String,
    /// RPC password (must match `-rpcpassword` on the node).
    pub rpc_password: String,
    /// Milliseconds between consecutive `getblocktemplate` polls (minimum 100).
    pub poll_interval_ms: u64,
    /// Expected chain name, validated against `getblockchaininfo.chain`.
    pub network: String,
    /// BIP feature rules to include in the `getblocktemplate` request object.
    /// Left empty by default for maximum AZCOIN compatibility — the node will
    /// return a template without assuming any soft-fork features.
    /// Set to `["segwit"]` only if the chain has SegWit activated.
    #[serde(default)]
    pub template_rules: Vec<String>,
}

impl Config {
    /// Read and validate a configuration file from `path`.
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config file: {}", path.display()))?;
        let config: Config = toml::from_str(&content)
            .with_context(|| format!("failed to parse config file: {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        anyhow::ensure!(!self.rpc_url.is_empty(), "rpc_url must not be empty");
        anyhow::ensure!(
            self.poll_interval_ms >= 100,
            "poll_interval_ms must be >= 100 (got {})",
            self.poll_interval_ms
        );
        anyhow::ensure!(
            !self.network.is_empty(),
            "network must not be empty"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn load_minimal_config() {
        let dir = std::env::temp_dir().join("azcoin_cfg_test_minimal");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        write!(
            f,
            r#"
rpc_url = "http://127.0.0.1:18443"
rpc_user = "u"
rpc_password = "p"
poll_interval_ms = 500
network = "regtest"
"#
        )
        .unwrap();
        let cfg = Config::load(&path).unwrap();
        assert_eq!(cfg.rpc_url, "http://127.0.0.1:18443");
        assert!(cfg.template_rules.is_empty(), "default should be empty");
    }

    #[test]
    fn load_config_with_template_rules() {
        let dir = std::env::temp_dir().join("azcoin_cfg_test_rules");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        write!(
            f,
            r#"
rpc_url = "http://127.0.0.1:18443"
rpc_user = "u"
rpc_password = "p"
poll_interval_ms = 500
network = "regtest"
template_rules = ["segwit"]
"#
        )
        .unwrap();
        let cfg = Config::load(&path).unwrap();
        assert_eq!(cfg.template_rules, vec!["segwit"]);
    }

    #[test]
    fn reject_empty_rpc_url() {
        let dir = std::env::temp_dir().join("azcoin_cfg_test_reject");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        write!(
            f,
            r#"
rpc_url = ""
rpc_user = "u"
rpc_password = "p"
poll_interval_ms = 500
network = "regtest"
"#
        )
        .unwrap();
        assert!(Config::load(&path).is_err());
    }

    #[test]
    fn accept_custom_network_name() {
        let dir = std::env::temp_dir().join("azcoin_cfg_test_custom_net");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        write!(
            f,
            r#"
rpc_url = "http://127.0.0.1:18443"
rpc_user = "u"
rpc_password = "p"
poll_interval_ms = 500
network = "azcoin-main"
"#
        )
        .unwrap();
        let cfg = Config::load(&path).unwrap();
        assert_eq!(cfg.network, "azcoin-main");
    }
}
