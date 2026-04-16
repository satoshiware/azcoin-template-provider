# azcoin-template-provider **0.2.0**

Stable baseline for the AZCOIN Stratum V2 mining path. This service sits between `azcoind` and `pool_sv2`: it polls the node for block templates, converts them into SV2 Template Distribution messages, pushes fresh work to the pool, accepts `SubmitSolution` when a block is found, assembles the full block, and submits it via `submitblock`.

**Release 0.2.0** is the first clean baseline where live template delivery, block submission, and on-chain reward crediting have been proven end to end. This document matches crate version **0.2.0** (`Cargo.toml`).

---

## Goal

- Poll `azcoind` for fresh block templates (`getblocktemplate`).
- Convert templates into SV2 Template Distribution messages (`NewTemplate`, `SetNewPrevHash`).
- Push fresh work to `pool_sv2` on an ongoing basis (live roll-forward).
- Receive `SubmitSolution` from the pool, assemble full block hex, call `submitblock` on `azcoind`.
- Cache templates by SV2 `template_id` so solved blocks reconstruct against the correct snapshot.

---

## Scope of 0.2.0

### Included

- `getblocktemplate` polling from the AZCoin node RPC.
- Initial SV2 template distribution after `SetupConnection` + `CoinbaseOutputConstraints`.
- Live SV2 template roll-forward when the poller detects meaningful template changes.
- `SubmitSolution` (message type **118** / `0x76`) decode and handling.
- Full block assembly from solved template + coinbase, then `submitblock`.
- Template-id cache for solved-template lookup (bounded LRU-style by height key).
- BIP34 coinbase height prefix in `NewTemplate.coinbase_prefix`.
- Witness commitment output in `NewTemplate` when `default_witness_commitment` is present.
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
  └─ RPC: getblocktemplate / submitblock
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
│   ├── health.rs     # startup connectivity & network match
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
2. **Template-id cache** — Solved blocks use the cached GBT snapshot for the submitted `template_id`, not only the latest template.
3. **BIP34 height** — `coinbase_prefix` carries correct BIP34-encoded block height for `NewTemplate`.
4. **Witness commitment** — When `default_witness_commitment` is set, the placeholder coinbase includes the zero-value witness-commitment output.
5. **Dedicated read/write codec state** — After init, the TCP stream splits: one task owns the write path and its own `codec_sv2::State`; the read loop keeps a clone for decrypting inbound frames. This removed starvation where the writer blocked behind the reader so the pool mined stale work.
6. **Broadcast depth** — Larger `broadcast` capacity reduces drops during bursty template updates (watch for `SV2 template update receiver lagged` if the system is overloaded).

### Why the read/write split mattered

Unhealthy pattern (older builds): new templates were discovered quickly, but the writer shared one mutex-protected codec with the read loop → writer blocked behind reads → pool stayed on old template IDs → stale or side-chain blocks.

Healthy signals after the fix: `skipped_intermediate` at or near **0** during normal roll-forward, no repeated `SV2 template update receiver lagged`, `submitblock: node accepted block` on current work.

---

## Data flow (implementation)

1. **`poller`** calls `getblocktemplate`, builds [`AzcoinTemplate`](src/template.rs), updates a `watch` channel, and on meaningful change sends [`TemplateUpdatePayload`](src/template.rs) on a `broadcast` channel for live SV2 pushes.
2. **`tp_server`** completes Noise NX, `SetupConnection` (Template Distribution, protocol version 2), reads `CoinbaseOutputConstraints`, sends initial `NewTemplate` + `SetNewPrevHash`, then runs a read loop plus a writer task subscribed to template broadcasts.
3. **Inbound `SubmitSolution`** — Parsed in `log_and_dispatch_post_init_sv2_frame`; block bytes built in `block_bytes_from_submit_solution`; submitted with [`RpcClient::submit_block`](src/rpc.rs).

Framing note: outbound Template Distribution uses **`extension_type == 0`** and **`channel_msg == false`**, consistent with common-message framing and typical `pool_sv2` classifiers.

---

## Configuration

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `rpc_url` | string | yes | — | JSON-RPC endpoint, e.g. `http://127.0.0.1:8332` |
| `rpc_user` | string | yes | — | RPC username |
| `rpc_password` | string | yes | — | RPC password |
| `poll_interval_ms` | integer | yes | — | Poll interval in ms (minimum 100) |
| `network` | string | yes | — | Expected chain name from `getblockchaininfo` |
| `template_rules` | string[] | no | `[]` | BIP rules for `getblocktemplate` |
| `tp_listen_address` | string | no | `0.0.0.0:8442` | TCP for SV2 Noise listener |
| `authority_public_key` | string | no | `""` | Noise authority public key (64 hex); empty disables SV2 |
| `authority_secret_key` | string | no | `""` | Noise authority secret key (64 hex) |

Copy and edit the example file:

```bash
cp config/azcoin-template-provider.toml.example config/azcoin-template-provider.toml
```

Add `config/azcoin-template-provider.toml` to `.gitignore` if it holds secrets.

---

## Build, test, run

```bash
cargo build --release
cargo test    # 17 unit tests (config, rpc submitblock results, template change detection, fixtures)
```

```bash
cargo run
# or
cargo run -- --config /path/to/config.toml
RUST_LOG=debug cargo run
```

If authority keys are empty, the service runs **poller-only** (no SV2 listener).

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
| **SegWit** | `getblocktemplate` defaults to `{}`; use `template_rules` for `segwit` when the chain supports it. |
| **Chain name** | `network` in config must match `getblockchaininfo.chain`. |
| **RPC schema** | Optional fields use `#[serde(default)]` (e.g. `default_witness_commitment`, `weightlimit`). |
| **`submitblock`** | `None` = accepted, `Some(reason)` = rejected (Bitcoin Core convention). |

If `azcoind` adds fields, extend `Rpc*` types in `src/template.rs` and extend fixtures under `testdata/`.

---

## What “template changed” means

| Change | Log |
|--------|-----|
| `previousblockhash` differs | New block on the network — template builds on a new tip. |
| Same prev hash, tx set or coinbase value differs | Template updated (mempool changed). |
| Only `curtime` moves | Debug “unchanged” — ignored to reduce noise. |

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|----------------|-----|
| HTTP / RPC errors | Node down or wrong `rpc_url` | Start `azcoind`, verify URL/port |
| HTTP 401 | Bad credentials | Match `rpc_user` / `rpc_password` |
| Network mismatch | Wrong `network` | Set to `getblockchaininfo.chain` |
| Authority key errors | Invalid hex keys | Fix Noise keypair in config |
| SV2 disabled | Empty authority keys | Set keys or use poller-only mode |
| `getblocktemplate` [-9] | IBD | Wait for sync |
| Repeated lag warnings | Bursty templates vs buffer | Tune poll interval / capacity; check node load |

---

## Release statement (0.2.0)

Template Provider **0.2.0** is the stable baseline that demonstrates: stable live template roll-forward, correct solved-template reconstruction, successful `submitblock` acceptance, on-chain blocks, and operator-side reward visibility through normal coinbase flow — **not** a complete payout product.

**Short version:** it sends the right work, receives solved blocks, gets them accepted, and produces real on-chain rewards. Per-miner payout systems are out of scope for this crate.

---

## License

See `LICENSE` in this repository.
