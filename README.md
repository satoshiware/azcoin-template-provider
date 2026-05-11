# azcoin-template-provider **0.2.0**

**Stable, released.** This is the production baseline for the AZCOIN Stratum V2 mining path. The service sits between `azcoind` and `pool_sv2`: it polls the node for block templates, converts them into SV2 Template Distribution messages, pushes fresh work to the pool, accepts `SubmitSolution` when a block is found, assembles the full block, and submits it via `submitblock`.

**Release 0.2.0** is done: `pool_sv2` compatibility for template identity, `CoinbaseOutputConstraints`, and `RequestTransactionData`, plus split read/write codec, live roll-forward, and block submission. This document matches crate version **0.2.0** (`Cargo.toml`).

**Super-node operators:** step-by-step checks, systemd/journal workflows, installs, rollback, and failure triage → [docs/template-provider-runbook.md](docs/template-provider-runbook.md).

**Program status & testing (leadership):** [docs/template-provider-status-report.md](docs/template-provider-status-report.md) — scope, live verification, wishlist.

**Release checklist & dry-run:** [docs/template-provider-release-checklist.md](docs/template-provider-release-checklist.md) — build, package, Profile A install, rollback, GitHub steps, optional `sc-node/azpool/templar` copy experiment.

---

## Goal

- Poll `azcoind` for fresh block templates (`getblocktemplate`) on a fixed cadence (`poll_interval_ms`) as a perpetual safety fallback.
- Connect to AZCoin Core ZMQ Publishers on **`rawtx`**, **`hashblock`**, and **`sequence`** (separate Subscriber connect URLs) for low-latency wakeup hints only — authoritative templates **always** come from **`getblocktemplate`** after every wakeup or poll tick; **`submitblock`** stays JSON-RPC unchanged.
- Convert templates into SV2 Template Distribution messages (`NewTemplate`, `SetNewPrevHash`).
- Push fresh work to `pool_sv2` on an ongoing basis (live roll-forward).
- Receive `SubmitSolution` from the pool, assemble full block hex, call `submitblock` on `azcoind`.
- Cache templates by SV2 `template_id` so solved blocks reconstruct against the correct snapshot.

---

## Scope of 0.2.0

### Included

- **`getblocktemplate` polling plus ZMQ (`rawtx` / `hashblock` / `sequence`) wakeup hints** toward the AZCoin node.
- Initial SV2 template distribution after `SetupConnection` + `CoinbaseOutputConstraints`.
- Live SV2 template roll-forward when the poller detects **chain-tip changes** (`previousblockhash` / height vs last broadcast), or mempool growth that clears **`fee_threshold`** without exceeding **`max_template_transactions`** (fee-threshold path applies only while the chain tip matches the last pushed template — see **`config/azcoin-template-provider.toml.example`** comments).
- `SubmitSolution` (message type **118** / `0x76`) decode and handling.
- Full block assembly from solved template + coinbase, then `submitblock`.
- Monotonic `template_id` allocation with exact snapshot caching by allocated ID.
- BIP34 coinbase height prefix in `NewTemplate.coinbase_prefix`.
- Witness commitment output in `NewTemplate` when `default_witness_commitment` is present.
- `CoinbaseOutputConstraints` persistence plus size/sigops gating before templates are sent.
- `RequestTransactionData` success/error handling using cached transaction data.
- Startup log of the exact authority public key to paste into `pool_sv2` config.
- Dedicated read vs write `codec_sv2::State` so the live template writer is not starved by the session read loop.
- Deeper broadcast buffer for bursty template updates (see `TEMPLATE_BROADCAST_BUFFER_DEPTH` in `main.rs`).
- Structured logs for template push, submit flow, and node acceptance/rejection.

### Not included (by design)

- Per-miner payout accounting or worker-level share ledger.
- Payout transaction creation or pool-side credit balances.
- Dashboard/API as authoritative truth for miner connection state.
- Broad protocol redesign beyond the narrow Template Provider role.

---

## High-level architecture

```text
azcoind
  └─ JSON-RPC (required): getblockchaininfo, getblocktemplate, submitblock
  └─ ZMQ Publisher (recommended): rawtx / hashblock / sequence → wakeup hints only
       │
       ▼
azcoin-template-provider
  ├─ poller: watches for new templates, broadcasts meaningful changes
  ├─ SV2 TP server: Noise + SetupConnection + Template Distribution
  └─ SubmitSolution handler: assembles full block, calls submitblock
       │
       ▼
pool_sv2
  ├─ receives template updates
  ├─ distributes work downstream
  ├─ accepts shares
  └─ sends SubmitSolution on block find
       │
       ▼
translator / miners
```

---

## Deployment profiles

Development and builds happen in this repository only. Two on-disk layouts appear in the field; use **one** per host unless you are deliberately migrating.

### Profile A — Super-node layout (current live fleet)

| Concept | Typical path |
|--------|-------------------|
| Installed Template Provider binary | `/opt/azcoin-super/templar/bin/azcoin-template-provider` |
| Installed config | `/etc/azcoin-super/templar/azcoin-template-provider.toml` |
| systemd unit | `azcoin-template-provider.service` |
| Service user / group | `azcoin-templar` / `azcoin-templar` |
| Working directory / state | `/var/lib/azcoin-super/templar` |

**Operational default:** production super-nodes already on Profile A should **stay on Profile A** until a deliberate, tested migration (paths, user, unit, automation).

### Profile B — Standalone / CEO installer layout (alternative)

| Concept | Typical path |
|--------|-------------------|
| Installed binary | `/usr/local/bin/azcoin-template-provider` |
| Config | `/etc/templar/azcoin-template-provider.toml` |
| Service user / group | `templar` / `templar` |
| Runtime / log dirs (typical) | `/var/lib/templar`, `/var/log/templar` |

Treat Profile B as **installer-specific** until your organisation’s packages and acceptance checks match it end-to-end.

### External `pool_sv2` / sv2-apps

**pool_sv2** (sv2-apps) is **external** to this repository. The pool connects inbound to **`tp_listen_address`** over the network; it **may run on a different host** than the Template Provider. This service is **not** payout or accounting authority — do not treat **`coinbase_output_count`** in logs as miner payout truth (it is SV2 placeholder / construction metadata).

### ZMQ naming contract

| Side | Role | Keys |
|------|------|------|
| **AZCoin Core** (`azcoin.conf`) | PUB **bind** options | `zmqpubrawtx=…`, `zmqpubhashblock=…`, `zmqpubsequence=…` |
| **Template Provider** (TOML) | SUB **connect** URLs | `zmq_endpoint_rawtx`, `zmq_endpoint_hashblock`, `zmq_endpoint_sequence` |

### Alignment with this release (`config` + ZMQ subscriber)

Startup **rejects empty** any of the three `zmq_endpoint_*` strings (`Config::validate` in **`src/config.rs`**). The background subscriber then **connects to all three** URLs and **subscribes** to topics **`rawtx`**, **`hashblock`**, and **`sequence`** (`src/zmq_wakeup.rs`). Configure **AZCoin Core** with **`zmqpubrawtx`**, **`zmqpubhashblock`**, and **`zmqpubsequence`** on bind URLs that match those connect targets (ports are site-specific).

**This README does not configure `/opt`, `/etc`, or systemd.** Copy artifacts from your CI or release build outputs.

`cargo build --release` pulls the **`zmq`** crate; **`zmq-sys`** is configured with vendored **`zeromq-src`**, so builders typically pick up a statically linked-ish libzmq without installing `libzmq` separately (override only if your organisation pins system linking).

### AZCoin Core ZMQ (`rawtx` / `hashblock` / `sequence`)

Templar **always** runs a background SUB socket that **connects to all three** configured endpoints and subscribes to **`rawtx`**, **`hashblock`**, and **`sequence`**. Multipart bodies are **not** parsed for mining templates — every signal only schedules another **`getblocktemplate`** RPC pass (debounced). **`poll_interval_ms`** remains the perpetual backup if ZMQ disconnects, errors, or is quiet; reconnect uses `zmq_reconnect_backoff_ms` with structured **`event=zmq_error`** lines that include **`polling_fallback_active=true`**.

**Publisher flags on AZCoin Core** (example — align ports with your `zmq_endpoint_*` values):

```text
zmqpubrawtx=tcp://127.0.0.1:29333
zmqpubhashblock=tcp://127.0.0.1:29334
zmqpubsequence=tcp://127.0.0.1:29335
```

Legacy config keys such as **`zmq_enabled`** or a single **`zmq_endpoint`** are **ignored** (not part of the current schema); ZMQ wakeup cannot be disabled via TOML.

Publishers are usually **unsigned / unauthenticated** — bind **`127.0.0.1`** or constrained internal IPs only.

**Verify:**

```bash
azcoin-cli getzmqnotifications

sudo journalctl -u azcoin-template-provider.service -n 240 --no-pager \
  | grep -E 'event="zmq_(subscriber_ready|subscriber_starting)"|event="template_refresh_trigger"' || true
```

---

### Safe manual install / update (run on the deployment host — not from CI)

The commands below assume **Profile A** paths. For **Profile B**, substitute binary, config, and ownership paths from [Deployment profiles](#deployment-profiles). Adjust further only if your site uses a different layout.

```bash
# Build (on a builder or checkout)
cargo build --release
# Artifact: ./target/release/azcoin-template-provider

# Install binary (requires appropriate privileges)
sudo install -o root -g root -m 0755 \
  target/release/azcoin-template-provider \
  /opt/azcoin-super/templar/bin/azcoin-template-provider

# Config: copy the example ONLY when creating a fresh config (do not overwrite secrets)
sudo install -o root -g azcoin-templar -m 0640 \
  config/azcoin-template-provider.toml.example \
  /etc/azcoin-super/templar/azcoin-template-provider.toml.new
# Then merge settings into your real file and remove *.new once satisfied.

sudo systemctl restart azcoin-template-provider.service
sudo systemctl status azcoin-template-provider.service --no-pager
sudo journalctl -u azcoin-template-provider.service -n 120 --no-pager
sudo journalctl -u azcoin-template-provider.service -f
```

Prefer `install`/`cp` with explicit modes; restart only after validating config.

---

### Readiness / health check CLI

There is **no HTTP health server** by design.

- **`--health-check`** — Loads the TOML config (via `--config` if set), verifies JSON-RPC connectivity and that `getblockchaininfo.chain` is **`main`** (built into the binary), and exits **0** on success without starting polling, the SV2 listener, or ZMQ subscriber wiring. Intended for scripted probes (e.g. `ExecStartPost` wrappers, Consul, Prometheus blackbox exporter via script).

```bash
./target/release/azcoin-template-provider --health-check \
  --config /etc/azcoin-super/templar/azcoin-template-provider.toml
```

**Follow-up (optional):** A dedicated `SIGUSR`-triggered readiness file or NOTIFY socket could extend observability without new frameworks; `--health-check` is the smallest in-process check today.

---

### Structured log events

**Operational defaults:** At **`RUST_LOG=info`** (the default subscriber filter unless you export `RUST_LOG`), **`journalctl`/`stdout` favors stable audit lines.** Grep **`event=`** for lifecycle and submission summaries: `grep event=` or `journalctl … | grep 'event='`. Low-level internals (Noise steps, SV2 framing, broadcast queue bookkeeping, `write_td_frame`) are **`debug`** or **`trace`** so they do not overwhelm operators at default verbosity.

Raise verbosity when diagnosing protocol issues:

```bash
RUST_LOG=azcoin_template_provider=debug,info ./target/release/azcoin-template-provider
# Finer protocol stepping (Noise bytes, TD frame internals):
RUST_LOG=azcoin_template_provider=trace,info ./target/release/azcoin-template-provider
```

`warn!` / `error!` calls are unchanged and stay visible under the default filter.

Logs use `tracing` with wall-clock **timestamps on each line** (`tracing_subscriber::fmt::time::SystemTime`). When **`log_file`** is set in TOML, the same structured stream is **appended** to that path **in addition to** stdout; the parent directory must already exist and be writable (the service does not create parent directories). Filter or ship logs by the stable **`event`** field where present:

| `event` | Meaning |
|---------|---------|
| `template_provider_startup` | Main services about to run (channels ready, SV2 mode flag set). |
| `rpc_connectivity_ready` | Startup JSON-RPC handshake and chain (`main`) verification succeeded (`health`); logs `expected_network` and `template_rules` as binary-built values. |
| `health_check_complete` | `--health-check` ran successfully before exit. |
| `pool_connected` | SV2 SetupConnection negotiated; Template Distribution channel ready (`peer`). |
| `pool_disconnected` | Session ended (TCP hangup, EOF, decode failure, handler error — see `reason` / `detail`). |
| `template_loaded` | First GBT snapshot received an SV2 `template_id`. |
| `template_changed` | Template differs from prior (poller semantics; see `change_kind`). |
| `zmq_subscriber_starting` / `zmq_subscriber_ready` | Background ZMQ Subscriber thread spun up / all three topics subscribed. |
| `zmq_message_received` | First-frame topic classified as UTF-8 vs binary plus aggregate payload length (**no hex dump**). |
| `template_refresh_trigger` | Schedules RPC refresh (`reason`: `poll`, `zmq_rawtx`, `zmq_hashblock`, `zmq_sequence` — surfaced at **`debug`** verbosity). |
| `zmq_error` | Socket/recv/send failure, wakeup channel dropout, or subscribe-loop exit (look for **`polling_fallback_active=true`** — polls continue). |
| `template_update_suppressed` | Mempool-only GBT refresh skipped for SV2 broadcast (`reason=fee_delta_below_threshold`, **`debug`**). |
| `template_rejected` | Mempool-only candidate failed `max_template_transactions` after fee threshold (`reason=max_template_transactions_exceeded`, **`warn`**). |
| `zmq_backoff_sleep` | Subscriber sleeping before reconnect. |
| `template_sent` | `NewTemplate` + `SetNewPrevHash` written to SV2 (`peer`, `template_id`, `previous_block_hash`, placeholder output count, witness flag). |
| `solution_received` | `SubmitSolution` decoded (`peer`, `template_id`). |
| `submitblock_called` | About to invoke `submitblock` (`block_hash` if derivation from assembled block succeeded). |
| `submitblock_result` | Outcome (`outcome`: `accepted`, `rejected_by_node`, `rpc_transport_or_envelope_failure`, `block_assembly_failed`, `template_cache_miss`; `reject_reason` when rejected). |
| `azcoin_rpc_error` | JSON-RPC/HTTP/deserialization failure (**passwords never logged**). |

Template-related events include **`template_id`**, **`height`**, **`previous_block_hash`**, and where applicable **`witness_commitment_included`**, **`coinbase_output_count`** (SV2 **placeholder** output count before pool reserved space).

---

### Journal examples (grep on `event=`)

```bash
sudo journalctl -u azcoin-template-provider.service -f --no-pager | grep event=
```

---

**Repository layout:**

```
azcoin-template-provider/
├── Cargo.toml
├── config/azcoin-template-provider.toml.example
├── src/
│   ├── main.rs       # CLI, wiring, template broadcast depth
│   ├── config.rs     # TOML load & validation
│   ├── rpc.rs        # JSON-RPC client (incl. submitblock)
│   ├── template.rs   # RPC types, AzcoinTemplate, change detection
│   ├── poller.rs     # getblocktemplate loop → watch + broadcast
│   ├── health.rs     # startup connectivity & mainnet chain check
│   └── tp_server.rs  # Noise, SV2 TD, live push, SubmitSolution
├── testdata/getblocktemplate_regtest.json
└── README.md
```

Typical deployment paths (adjust for your host):

| Piece | Example path |
|-------|----------------|
| This repo | `~/repos/azcoin-template-provider` |
| Pool (`pool_sv2`) | e.g. under your `sv2-apps` checkout |
| Pool config | e.g. `/etc/azcoin-super/pool/pool-config.toml` |
| Node | `azcoind` with `azcoin.conf` and datadir |

---

## Proven runtime behavior (0.2.0)

- Pool receives live `NewTemplate` and `SetNewPrevHash`.
- Pool sends `SubmitSolution` on found block.
- Template Provider decodes `SubmitSolution`, resolves template via cache, assembles block.
- `azcoind` accepts the block via `submitblock` (null result).
- Accepted blocks land on-chain; rewards credit to the payout path configured in pool/node policy (immature coinbase outputs in the operator wallet is the common deployment pattern).

**What 0.2.0 does not prove:** per-miner accounting, authoritative worker ledgers, or a payout engine — build those as separate services.

---

## Critical fixes that define the clean baseline

1. **`SubmitSolution`** — Post-setup frames with `msg_type == 118` are decoded and routed to block assembly + `submitblock`.
2. **Monotonic template IDs** — Every meaningful template update gets a unique allocated `template_id`; solved blocks and transaction-data requests resolve against the exact cached snapshot for that ID.
3. **`RequestTransactionData`** — The provider now returns `RequestTransactionDataSuccess` for cached templates and `RequestTransactionDataError` with `template-id-not-found` for unknown/stale IDs.
4. **Coinbase output constraints** — The latest per-session `CoinbaseOutputConstraints` are persisted and used to reject templates that cannot safely fit the pool’s reserved output bytes/sigops.
5. **BIP34 height** — `coinbase_prefix` carries correct BIP34-encoded block height for `NewTemplate`.
6. **Witness commitment** — When `default_witness_commitment` is set, the placeholder coinbase includes the zero-value witness-commitment output.
7. **Dedicated read/write codec state** — After init, the TCP stream splits: one task owns the write path and its own `codec_sv2::State`; the read loop keeps a clone for decrypting inbound frames. This removed starvation where the writer blocked behind the reader so the pool mined stale work.
8. **Broadcast depth** — Larger `broadcast` capacity reduces drops during bursty template updates (watch for `SV2 template update receiver lagged` if the system is overloaded).

### Why the read/write split mattered

Unhealthy pattern (older builds): new templates were discovered quickly, but the writer shared one mutex-protected codec with the read loop → writer blocked behind reads → pool stayed on old template IDs → stale or side-chain blocks.

Healthy signals after the fix: `skipped_intermediate` at or near **0** during normal roll-forward, no repeated `SV2 template update receiver lagged`, `submitblock: node accepted block` on current work.

---

## Data flow (implementation)

1. **`poller`** calls `getblocktemplate`, builds [`AzcoinTemplate`](src/template.rs), allocates `template_id` for **eligible** broadcasts (chain-tip rollover always wins; mempool-only pushes need fee delta **`≥ fee_threshold`** and **`transactions.len() ≤ max_template_transactions`**), updates a `watch` channel with the latest **accepted** [`TemplateSnapshot`](src/template.rs), and sends [`TemplateUpdatePayload`](src/template.rs) on `broadcast` for live SV2 pushes.
2. **`tp_server`** completes Noise NX, `SetupConnection` (Template Distribution, protocol version 2), reads `CoinbaseOutputConstraints`, validates the current template against the reserved coinbase headroom, sends initial `NewTemplate` + `SetNewPrevHash`, then runs a read loop plus a writer task subscribed to template broadcasts.
3. **Inbound `SubmitSolution` / `RequestTransactionData`** — Parsed in `log_and_dispatch_post_init_sv2_frame`; solved blocks are assembled from the exact cached snapshot and submitted with [`RpcClient::submit_block`](src/rpc.rs); transaction-data requests return the cached non-coinbase transactions plus excess data.

Framing note: outbound Template Distribution uses **`extension_type == 0`** and **`channel_msg == false`**, consistent with common-message framing and typical `pool_sv2` classifiers.

---

## Configuration

Expected AZCOIN chain validation and `getblocktemplate` rules (`["segwit"]`) are **compiled into the binary** for production — they are not TOML settings. ZMQ endpoint addresses and push policy knobs are configurable (see **`config/azcoin-template-provider.toml.example`**, including **CLI flags**, **RPC/ZMQ naming**, and **non-config constants** in the file header comments). **Install paths on disk** follow **Profile A** or **Profile B** (see [Deployment profiles](#deployment-profiles)); the **same TOML field names** apply to both.

### JSON-RPC whitelist (AZCoin Core `rpcwhitelist` reference)

Operational **minimum** RPC methods templar invokes in normal steady state:

| Method | Role |
|--------|------|
| `getblockchaininfo` | Startup chain (`main`) + health checks |
| `getblocktemplate` | Authoritative block templates (`rules: ["segwit"]`, hardcoded) |
| `submitblock` | `SubmitSolution` → assembled block submission |

Optional / internal-only helpers (**defined in [`src/rpc.rs`](src/rpc.rs)** but **not wired** into `main` steady-state loops today — diagnostics or future tooling only):

| Method | Role |
|--------|------|
| `getbestblockhash` | Tip hash helper (Bitcoin / AZCoin Core name — **not** `getbesthash`) |
| `getblockheader` | Header diagnostic helper |

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `rpc_url` | string | yes | — | JSON-RPC endpoint, e.g. `http://127.0.0.1:8332` |
| `rpc_user` | string | yes | — | RPC username |
| `rpc_password` | string | yes | — | RPC password |
| `poll_interval_ms` | integer | yes | — | Poll interval in ms (minimum 100; perpetual ZMQ-loss fallback) |
| `zmq_endpoint_rawtx` | string | yes¹ | `tcp://127.0.0.1:29333` | SUB connect URL for **`rawtx`** (must be non-empty at load) |
| `zmq_endpoint_hashblock` | string | yes¹ | `tcp://127.0.0.1:29334` | SUB connect URL for **`hashblock`** (must be non-empty at load) |
| `zmq_endpoint_sequence` | string | yes¹ | `tcp://127.0.0.1:29335` | SUB connect URL for **`sequence`** (must be non-empty at load) |

¹ serde defaults apply, but **`Config::load` validation** rejects whitespace-only / empty values for all three.
| `fee_threshold` | integer | no | `5000` | Min satoshi **fee-sum increase** vs last pushed template **at same tip** to SV2-push a mempool-only update |
| `max_template_transactions` | integer | no | `5000` | Caps non-coinbase tx count on **fee-threshold-qualified** mempool-only pushes (**ignored on chain-tip rollover**) |
| `log_file` | string | no | `""` | Append structured logs here as well as stdout; empty disables file sink |
| `zmq_receive_timeout_ms` | integer | no | `1000` | ZMQ `RECVTIMEO` for subscriber thread recv |
| `zmq_reconnect_backoff_ms` | integer | no | `1000` | Sleep before restarting SUB after transport errors |
| `zmq_wakeup_debounce_ms` | integer | no | `250` | Debounce coalescing for bursty ZMQ signals |
| `tp_listen_address` | string | no | `0.0.0.0:8442` | TCP for SV2 Noise listener |
| `authority_public_key` | string | no | `""` | Hex-encoded 32-byte secp256k1 x-only public key for `pool_sv2` `[template_provider_type.Sv2Tp].public_key`; empty disables SV2 |
| `authority_secret_key` | string | no | `""` | Hex-encoded 32-byte secp256k1 secret key matching `authority_public_key` |

Copy and edit the example file:

```bash
cp config/azcoin-template-provider.toml.example config/azcoin-template-provider.toml
```

Add `config/azcoin-template-provider.toml` to `.gitignore` if it holds secrets.

---

## Build, test, run

```bash
cargo build --release
cargo test    # unit tests (config, RPC, template, constraints, tx-data responses)
```

```bash
cargo run
# or
cargo run -- --config /path/to/config.toml
RUST_LOG=debug cargo run
# One-shot RPC readiness (exits immediately; systemd-friendly)
cargo run --release -- --health-check --config /path/to/config.toml
```

If authority keys are empty, the service runs **poller-only** (no SV2 listener).

### `pool_sv2` public key format

Paste the exact configured `authority_public_key` value into `pool_sv2` under:

```toml
[template_provider_type.Sv2Tp]
public_key = "<authority_public_key>"
```

The expected encoding is **hex**, not base58 or base58-check. The value is the raw **32-byte secp256k1 x-only public key**. On startup the provider logs the exact normalized hex string it expects the pool to use.

---

## Key logs (production)

**Pool — block and template flow:**

```bash
sudo journalctl -u pool-sv2.service -f -n 0 --no-pager | \
  grep -Ei 'Block Found|Propagating solution|Received: NewTemplate|Received: SetNewPrevHash|valid share|UpdateChannel'
```

**Template Provider — submit and lag:**

```bash
sudo journalctl -u azcoin-template-provider.service -f -n 0 --no-pager | \
  grep -Ei 'SubmitSolution|calling submitblock|submitblock:|skipped_intermediate|SV2 template update receiver lagged|dedicated (read|write) codec state'
```

**Quick retro — missed found blocks:**

```bash
sudo journalctl -u pool-sv2.service --since '30 minutes ago' --no-pager | \
  grep -Ei 'Block Found|Propagating solution'
```

### Healthy checklist

- Pool receives fresh `NewTemplate` / `SetNewPrevHash`.
- `SubmitSolution decode succeeded` → `calling submitblock RPC` → `submitblock: node accepted block (null result)`.
- `skipped_intermediate` ≈ 0; few or no `SV2 template update receiver lagged`.
- Wallet shows expected immature coinbase growth after accepted blocks (per your payout setup).

---

## Reward routing (operational truth)

Coinbase pays the addresses encoded by pool/template rules in your deployment. **Template Provider 0.2.0 does not implement per-miner payout splits** — the operator or pool layer must add share accounting, balances, and payout policy separately.

---

## Example verification (RPC)

```bash
azc -rpcwallet=wallet getbalances
azc -rpcwallet=wallet listtransactions "*" 50 0 true | jq '.[] | select(.generated == true)'
azc getblock <blockhash> 2
azc getblockheader <blockhash> true
azc getchaintips | jq --arg H '<blockhash>' '.[] | select(.hash == $H)'
```

---

## AZCOIN-specific compatibility

| Area | Behavior |
|------|----------|
| **SegWit** | Every production `getblocktemplate` call uses `rules: ["segwit"]` (hardcoded). |
| **Chain name** | Startup validates `getblockchaininfo.chain == "main"` (hardcoded expected chain). |
| **RPC schema** | Optional fields use `#[serde(default)]` (e.g. `default_witness_commitment`, `weightlimit`). |
| **`submitblock`** | `None` = accepted, `Some(reason)` = rejected (Bitcoin Core convention). |

If `azcoind` adds fields, extend `Rpc*` types in `src/template.rs` and extend fixtures under `testdata/`.

---

## What “template changed” means

| Change | SV2 broadcast |
|--------|----------------|
| `previousblockhash` or `height` differs vs **last pushed** template | **Always** (`NewTemplate` / `SetNewPrevHash`) — ignores `fee_threshold` and `max_template_transactions`. |
| Same chain tip, transaction set / coinbase value differs | **Only if** summed non-coinbase fees increased by **`≥ fee_threshold`** sats vs last push **and** `transactions.len() ≤ max_template_transactions`. |
| Only `curtime` moves | Debug “unchanged” — ignored to reduce noise. |

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|----------------|-----|
| HTTP / RPC errors | Node down or wrong `rpc_url` | Start `azcoind`, verify URL/port |
| HTTP 401 | Bad credentials | Match `rpc_user` / `rpc_password` |
| Chain mismatch | Node is not on **main** (e.g. testnet/regtest) | Run this Template Provider only against AZCOIN **main**; error: `AZCoin Core chain mismatch: expected main, got …` |
| Authority key errors | Invalid hex keys | Fix Noise keypair in config |
| SV2 disabled | Empty authority keys | Set keys or use poller-only mode |
| `getblocktemplate` [-9] | IBD | Wait for sync |
| Repeated lag warnings | Bursty templates vs buffer | Tune poll interval / capacity; check node load |

---

## Release statement (0.2.0)

Template Provider **0.2.0** is the **stable, released** line for AZCOIN: monotonic template identity, transaction-data responses, coinbase-output-constraint enforcement, explicit authority public-key guidance, split read/write codec, and `SubmitSolution` → `submitblock` — **not** a complete payout product.

**Short version:** it sends the right work, receives solved blocks, gets them accepted, and produces real on-chain rewards. Per-miner payout systems are out of scope for this crate. The core Template Provider surface is complete for 0.2.x unless you introduce new protocol or deployment requirements.

---

## License

See `LICENSE` in this repository.
