# azcoin-template-provider

Rust service that sits between `azcoind` and an SV2 mining pool.
It polls `azcoind` for block templates over JSON-RPC and exposes a
Noise-authenticated TCP listener where `pool_sv2` connects.  The current
phase proves transport-level connectivity: the RPC poller ingests live
templates, and the SV2 listener completes the Noise NX handshake with
connecting pools, establishing an encrypted channel.

## Project Structure

```
azcoin-template-provider/
├── Cargo.toml                                  # crate manifest & dependencies
├── config/
│   └── azcoin-template-provider.toml.example   # annotated reference config
├── src/
│   ├── main.rs       # entry point — CLI parsing, wiring, startup sequence
│   ├── config.rs     # TOML config loading & validation
│   ├── rpc.rs        # JSON-RPC 1.0 client (reqwest + Basic auth)
│   ├── template.rs   # RPC response types, AzcoinTemplate, change detection
│   ├── poller.rs     # async polling loop (publishes via watch channel)
│   ├── health.rs     # startup connectivity & network-match check
│   └── tp_server.rs  # SV2 Template Provider (Noise NX handshake)
├── testdata/
│   └── getblocktemplate_regtest.json   # fixture for deserialization tests
└── README.md
```

## Architecture

```
                           ┌─────────────────────────────────────┐
┌────────────┐  JSON-RPC   │  azcoin-template-provider           │
│  azcoind   │◄────────────│                                     │   Noise :8442
│  (node)    │────────────►│  poller ──watch──► tp_server ◄──────── pool_sv2
└────────────┘             │            channel  (Noise NX)      │
                           │                                     │
                           │  startup:                           │
                           │    config.rs  → load TOML           │
                           │    health.rs  → getblockchaininfo   │
                           │                                     │
                           │  concurrent tasks:                  │
                           │    poller.rs  → getblocktemplate    │
                           │    tp_server  → Noise handshake    │
                           └─────────────────────────────────────┘
```

**Data flow (per poll tick):**

1. `poller` calls `rpc.get_block_template()`.
2. `rpc` sends a JSON-RPC 1.0 POST to `azcoind` and deserializes the
   response into `RpcBlockTemplate`.
3. `template::AzcoinTemplate::from_rpc()` normalizes the raw data.
4. `template::AzcoinTemplate::describe_change()` compares against the
   previous template and returns a human-readable diff (or `None`).
5. The result is logged via `tracing` at the appropriate level.
6. The template is published through a `tokio::sync::watch` channel so
   `tp_server` always has access to the latest template.

## Current Scope

- Load configuration from a TOML file (`rpc_url`, `rpc_user`,
  `rpc_password`, `poll_interval_ms`, `network`, `template_rules`,
  `tp_listen_address`, `authority_public_key`, `authority_secret_key`).
- Connect to `azcoind` and verify connectivity via `getblockchaininfo`.
- Poll `getblocktemplate` on a configurable interval.
- Detect and log **template changes** (see below).
- Expose helper RPC wrappers: `getblockchaininfo`, `getblocktemplate`,
  `submitblock`, `getbestblockhash`, `getblockheader`.
- **SV2 TP (Noise)**: Bind a Noise-authenticated TCP listener on
  `tp_listen_address`, perform a full Noise NX handshake with each
  connecting pool, and keep the encrypted channel open.
- Share the latest polled template in-process via a `watch` channel
  (ready for the TP server to consume in the next phase).
- Graceful fallback to poller-only mode when authority keys are not
  configured.

## Non-Goals (for this phase)

- SV2 application-layer messages (`SetupConnection`, `NewTemplate`, etc.).
- Solved-block submission relay.
- Translator proxy integration.
- Block assembly or coinbase construction.
- systemd / Docker packaging.
- Metrics, Prometheus, or HTTP health endpoints.
- Persistent storage.
- Workspace-level Cargo changes.

## SV2 Template Provider (Noise Transport)

The `tp_server` module (`src/tp_server.rs`) implements the server-side
(responder) Noise NX handshake using `noise_sv2::Responder`.

**What works now:**
- TCP bind on the configured `tp_listen_address` (default `0.0.0.0:8442`)
- Full Noise NX handshake per connection:
  1. Read initiator's 64-byte ElligatorSwift ephemeral key
  2. Derive shared secrets, sign session certificate with authority key
  3. Send 234-byte response (ephemeral key + encrypted static key + cert)
  4. Encrypted transport established
- Detailed lifecycle logging: listener startup, connect, handshake start,
  handshake success, handshake failure reason, disconnect
- Holds a `watch::Receiver<Option<AzcoinTemplate>>` with the latest
  template (not yet consumed — ready for SV2 message layer)
- Graceful fallback: if authority keys are empty, the Noise listener is
  disabled and only the RPC poller runs

**What is explicitly NOT implemented:**
- SV2 application-layer message framing / parsing
- `SetupConnection` / `SetupConnection.Success` exchange
- `NewTemplate` / `SetNewPrevHash` message dispatch
- `SubmitSolution` handling
- Decryption of post-handshake SV2 frames (raw ciphertext is logged)

## AZCOIN-Specific Compatibility

This adapter targets **AZCOIN** (`azcoind`), a Bitcoin Core derivative.
The following design decisions ensure compatibility:

| Area | Assumption |
|---|---|
| **SegWit** | Not assumed.  `getblocktemplate` sends an empty object `{}` by default — no `"rules": ["segwit"]` unless explicitly configured via `template_rules`. |
| **Chain name** | The `network` config value is matched against the `chain` field returned by `getblockchaininfo`.  No hardcoded allowlist — any value the node reports is accepted. |
| **RPC schema** | Response structs use `#[serde(default)]` for every field that may be absent on AZCOIN (e.g. `weightlimit`, `default_witness_commitment`, `hash` on transactions).  Required fields are those present in every Bitcoin Core derivative: `version`, `previousblockhash`, `transactions`, `coinbasevalue`, `target`, `bits`, `height`, `curtime`, `mintime`. |
| **`submitblock`** | Returns `None` (accepted) or `Some("reason")` (rejected), matching Bitcoin Core conventions. |

### What if AZCOIN diverges further from Bitcoin Core RPC?

If `azcoind` adds or renames fields not yet covered, update the
`Rpc*` structs in `src/template.rs` and add a new JSON fixture in
`testdata/`.  All existing tests will keep passing because unknown
fields are silently ignored by serde.

## What "Template Changed" Means

The poller compares each new template against the previous one:

| Change detected | Log message |
|---|---|
| `previousblockhash` differs | **"new block"** — a new block was found on the network, so the template now builds on a different tip. |
| Same `previousblockhash` but transaction set or `coinbasevalue` differs | **"template updated"** — the mempool changed (new transactions arrived or old ones were evicted). |
| Nothing meaningful differs (only `curtime` changed) | Debug-level "Template unchanged" — no action needed. |

`curtime` changes on every poll because the node advances the block
timestamp.  This is intentionally **not** treated as a template change
to avoid log spam.

## Prerequisites

- Rust toolchain (stable, 1.70+)
- A running `azcoind` node with JSON-RPC enabled

## How to Build

```bash
cargo build
```

For a release binary:

```bash
cargo build --release
```

## How to Test

```bash
cargo test
```

**17 tests** across three modules:

| Module | Tests | What's covered |
|---|---|---|
| `config` | 4 | Minimal load, template_rules parsing, validation rejection, custom network names |
| `rpc` | 4 | `submitblock` result deserialization: null (accepted), "duplicate", "inconclusive", "high-hash" |
| `template` | 9 | Fixture parsing, missing-witness-field parsing, `from_rpc` field mapping, new-block detection, tx-set update, coinbase-only update, curtime-only (ignored), identical templates |

The test fixture at `testdata/getblocktemplate_regtest.json` is a
synthetic AZCOIN regtest response (no witness commitment, empty rules).
Replace it with a real capture from your `azcoind` node for maximum
fidelity — existing tests will still pass as long as the required fields
are present.

## Configuration Reference

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `rpc_url` | string | yes | — | JSON-RPC endpoint, e.g. `http://127.0.0.1:8332` |
| `rpc_user` | string | yes | — | RPC username |
| `rpc_password` | string | yes | — | RPC password |
| `poll_interval_ms` | integer | yes | — | Polling interval in ms (minimum 100) |
| `network` | string | yes | — | Expected chain name from `getblockchaininfo` |
| `template_rules` | string[] | no | `[]` | BIP rules for `getblocktemplate` request |
| `tp_listen_address` | string | no | `"0.0.0.0:8442"` | TCP address for the SV2 Noise listener |
| `authority_public_key` | string | no | `""` | Noise authority public key (64 hex chars). Empty = disable Noise. |
| `authority_secret_key` | string | no | `""` | Noise authority secret key (64 hex chars). Empty = disable Noise. |

See `config/azcoin-template-provider.toml.example` for a fully-commented
reference file.

## How to Configure

```bash
cp config/azcoin-template-provider.toml.example config/azcoin-template-provider.toml
# Edit the file to match your azcoind setup
```

> **Tip:** Add `config/azcoin-template-provider.toml` to your
> `.gitignore` so local credentials are never committed.

## How to Run

```bash
# Uses the default config path (config/azcoin-template-provider.toml)
cargo run

# Or specify a custom config file
cargo run -- --config /path/to/config.toml

# Increase log verbosity
RUST_LOG=debug cargo run
```

### Example Output

```
INFO  Loading configuration    path="config/azcoin-template-provider.toml"
INFO  Configuration loaded     rpc_url="http://127.0.0.1:8332" network="regtest" poll_ms=1000 tp_addr="0.0.0.0:8442"
INFO  Connecting to azcoind    url="http://127.0.0.1:8332"
INFO  RPC connection established  chain="regtest" blocks=200 headers=200 best_hash="7e4b..." ibd=false sync="100.0000%"
INFO  Health check passed      network="regtest" template_rules=[]
INFO  Starting SV2 Template Provider (Noise-authenticated)  tp_address="0.0.0.0:8442"
INFO  SV2 Template Provider listening (Noise-authenticated)  address=0.0.0.0:8442
INFO  Starting template poller interval_ms=1000
INFO  Initial template received  poll=1 height=201 prev_hash="7e4bac91..." tx_count=2 coinbase=5000037500
INFO  Incoming TCP connection  peer=192.168.1.50:54321
INFO  Noise handshake: waiting for initiator ephemeral key  peer=192.168.1.50:54321
INFO  Noise handshake: computing response  peer=192.168.1.50:54321
INFO  Noise handshake completed — encrypted transport established  peer=192.168.1.50:54321
INFO  Template changed: new block: height 201 -> 202, prev_hash aabb0011..44556677
INFO  SV2 client disconnected  peer=192.168.1.50:54321
```

### Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `HTTP request for RPC method 'getblockchaininfo' failed` | Node is down or `rpc_url` is wrong | Start `azcoind` and verify the URL/port |
| `RPC 'getblockchaininfo' returned HTTP 401` | Bad credentials | Check `rpc_user` / `rpc_password` match the node config |
| `network mismatch: config expects 'X' but azcoind reports 'Y'` | Wrong `network` value | Set `network` to the value `azcoind` actually reports |
| `authority keypair is invalid` | Bad or mismatched hex keys | Generate a valid secp256k1 keypair (see config example) |
| `authority keys not configured — SV2 TP listener disabled` | Keys are empty | Set `authority_public_key` / `authority_secret_key` in config |
| `Node is still performing initial block download` | Node is syncing | Wait for sync to complete, or ignore the warning |
| `RPC 'getblocktemplate' error [-9]` | Node is in IBD | `getblocktemplate` is unavailable during IBD — wait |
| Repeated `Failed to get block template` | Intermittent RPC issues | The poller retries automatically each tick |
