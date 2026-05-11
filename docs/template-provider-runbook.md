# AZCoin Template Provider — operational runbook

Linux-oriented procedures for operators. This document is **reference only**; it does not configure your host.

Most path-based commands below assume **Profile A (super-node layout)**. For **Profile B** (standalone / CEO-style installer paths), substitute the binary, config, and service user from [Deployment profiles](#deployment-profiles).

---

## Deployment profiles

### Profile A — Super-node (default for current live fleet)

| Item | Typical value |
|------|----------------|
| systemd unit | `azcoin-template-provider.service` |
| Binary | `/opt/azcoin-super/templar/bin/azcoin-template-provider` |
| Config | `/etc/azcoin-super/templar/azcoin-template-provider.toml` |
| User / group | `azcoin-templar` / `azcoin-templar` |
| Working / state dir | `/var/lib/azcoin-super/templar` |

**Stay on Profile A** unless you plan and test a deliberate migration (paths, user, systemd, automation).

### Profile B — Standalone / CEO installer (alternative)

| Item | Typical value |
|------|----------------|
| Binary | `/usr/local/bin/azcoin-template-provider` |
| Config | `/etc/templar/azcoin-template-provider.toml` |
| User / group | `templar` / `templar` |
| Runtime / logs | `/var/lib/templar`, `/var/log/templar` |

### External pool (`pool_sv2` / sv2-apps)

**pool_sv2** is **external software**; it can run **on another machine** than the Template Provider. Use routable **`tp_listen_address`**, firewall rules, and the pool’s SV2 Template Provider peer settings accordingly. This service does **not** implement miner payouts or ledger truth.

### ZMQ naming (Core vs Template Provider)

- **`azcoin.conf`:** `zmqpubrawtx`, `zmqpubhashblock`, `zmqpubsequence` (PUB binds).
- **Template Provider TOML:** `zmq_endpoint_rawtx`, `zmq_endpoint_hashblock`, `zmq_endpoint_sequence` (SUB connect URLs; **all three must be non-empty** at config load — `src/config.rs`). The process **subscribes** to topics **`rawtx`**, **`hashblock`**, and **`sequence`** (`src/zmq_wakeup.rs`).

---

## 1. Purpose

The AZCoin Template Provider is the super-node service that:

- Pulls mining block templates from AZCoin Core via **`getblocktemplate`** (`poll_interval_ms` backup), with **preferred low-latency ZMQ wakeup hints** (`rawtx`, `hashblock`, `sequence`; separate Publisher endpoints) layered on — **GBT stays authoritative**. **Important:** mempool-only broadcasts are gated by **`fee_threshold`** / **`max_template_transactions`** (`hashblock`/tip-roll templates are not gated by fees and ignore the txn cap).
- Serves templates to the local (or remote) SV2 pool over **Stratum V2 Template Distribution** (Noise + `NewTemplate` / `SetNewPrevHash`).
- Accepts `SubmitSolution` from the pool, assembles a full block, and submits it via **`submitblock`** on the node.

It is the authoritative **template + block-submission gateway** for that mining path. It does **not** replace AZCoin Core, the pool, or payout infrastructure.

---

## 2. Architecture role / non-goals

**In scope**

- Template freshness (polling + ZMQ wakes + mempool fee / size policy before SV2 broadcasts).
- Correct SV2 template identity (`template_id` caching).
- Forwarding solved blocks to the node RPC.

**Explicit non-goals (do not expect this service to)**

- Calculate miner payouts, splits, or balances.
- Perform SC-node or per-worker accounting.
- Hold or manage private keys, seeds, wallets, or custody.
- Interpret `coinbase_output_count` in logs as “how many payouts” — it reflects **SV2 placeholder / construction** metadata, **not** payout policy truth.

Operators own payout logic, wallet policy, and pool configuration elsewhere.

---

## 3. Key paths and service names (Profile A)

The table below lists **Profile A** (super-node). For **Profile B** paths, see [Deployment profiles](#deployment-profiles).

| Item | Path or name |
|------|----------------|
| systemd unit | `azcoin-template-provider.service` |
| Live binary | `/opt/azcoin-super/templar/bin/azcoin-template-provider` |
| Live config (TOML) | `/etc/azcoin-super/templar/azcoin-template-provider.toml` |
| Service user | `azcoin-templar` |
| Runtime state (typical layout) | `/var/lib/azcoin-super/templar` |
| Logs (stdout/journal plus optional **`log_file`**) | site-specific (`log_file` path must exist) |
| Related: AZCoin Core | `azcoind.service` |
| Related: SV2 pool | `pool-sv2.service` (may be remote; external to this repo) |

**Source/build workspace** (developer checkout) is separate from these paths unless you deliberately install into `/opt`.

---

## 4. Five-minute health verification checklist

Run in order; all should look sane before declaring “healthy.”

1. **Units up** — `azcoin-template-provider`, `azcoind`, and `pool-sv2` show `active (running)` where expected.
2. **No restart storm** — `systemctl status` shows low restart count / recent uptime unless you intentionally restarted.
3. **Structured events** — last few minutes include `event=template_provider_startup`, `event=rpc_connectivity_ready`, and (if SV2 enabled) `event=pool_connected` / `event=template_sent`.
4. **Core RPC** — node responds (`getblockchaininfo.chain` is **`main`** per binary validation; not stuck in unexpected error loops in templar logs).
5. **No critical error bursts** — `journalctl -p err` for the templar unit is quiet aside from known maintenance windows.

Copy/paste starters:

```bash
sudo systemctl is-active azcoind.service pool-sv2.service azcoin-template-provider.service

sudo systemctl status azcoin-template-provider.service --no-pager -l | head -n 25

sudo journalctl -u azcoin-template-provider.service --since "10 minutes ago" --no-pager | grep -E 'event=(template_provider_startup|rpc_connectivity_ready|pool_connected|template_sent|submitblock_)' || true
```

---

## 5. Runtime health-check command

The binary supports a **one-shot** RPC and config validation (**no steady-state SV2 listener, polling loop, or ZMQ subscriber thread**) suitable for probes:

```bash
sudo -u azcoin-templar /opt/azcoin-super/templar/bin/azcoin-template-provider \
  --health-check \
  --config /etc/azcoin-super/templar/azcoin-template-provider.toml
```

- Exit **0** means config loaded and JSON-RPC + **main** chain checks passed.
- Use in scripts or after config edits **before** relying on steady-state mining.

Adjust `sudo -u` if your site runs the check differently; the important part is invoking the **installed** binary with the **installed** config.

---

## 6. Safe binary install/update flow

**Principles:** build elsewhere (or CI), verify artifact, swap binary atomically-ish, restart one service, watch logs.

```bash
# On a builder with the repo (example)
cargo build --release
# Produced artifact (typical): target/release/azcoin-template-provider

# On the super-node host (privileged)
sudo install -o root -g root -m 0644 \
  /opt/azcoin-super/templar/bin/azcoin-template-provider \
  /opt/azcoin-super/templar/bin/azcoin-template-provider.bak."$(date -u +%Y%m%d%H%M%S)"

sudo install -o root -g root -m 0755 \
  ./azcoin-template-provider \
  /opt/azcoin-super/templar/bin/azcoin-template-provider

sudo systemctl restart azcoin-template-provider.service

sudo systemctl status azcoin-template-provider.service --no-pager -l

sudo journalctl -u azcoin-template-provider.service -n 120 --no-pager
```

- Do **not** paste RPC credentials into shells or tickets.
- **Config** updates are separate from binary updates — edit `/etc/azcoin-super/templar/azcoin-template-provider.toml` deliberately; then `restart` and verify logs.

---

## 7. Rollback flow

If a new binary misbehaves after restart:

```bash
# Identify the newest good backup next to the live binary (example naming from step 6)
ls -la /opt/azcoin-super/templar/bin/

sudo install -o root -g root -m 0755 \
  /opt/azcoin-super/templar/bin/azcoin-template-provider.bak.<TIMESTAMP> \
  /opt/azcoin-super/templar/bin/azcoin-template-provider

sudo systemctl restart azcoin-template-provider.service
sudo journalctl -u azcoin-template-provider.service -n 120 --no-pager
```

If the regression is **config**-driven:

```bash
sudo cp -a /path/to/known-good-backup/azcoin-template-provider.toml \
  /etc/azcoin-super/templar/azcoin-template-provider.toml

sudo systemctl restart azcoin-template-provider.service
```

Restore procedure should match your organisation’s backup policy for `/etc` and `/opt`.

---

## 8. Confirm service user, live binary path, and config path

```bash
# Unit file (may vary by distro layout; resolves actual ExecStart/User)
systemctl cat azcoin-template-provider.service | sed -n '1,120p'

# Effective user and argv
sudo systemctl show azcoin-template-provider.service -p User -p ExecStart --no-pager

# Sanity: binary readable/executable by service policy
sudo -u azcoin-templar test -x /opt/azcoin-super/templar/bin/azcoin-template-provider && echo OK

# Config readable (mode should be restrictive in production)
sudo ls -la /etc/azcoin-super/templar/azcoin-template-provider.toml
```

Expected anchors for this deployment model:

| Check | Expected |
|-------|-----------|
| User | `azcoin-templar` |
| Binary | `/opt/azcoin-super/templar/bin/azcoin-template-provider` |
| Config | `/etc/azcoin-super/templar/azcoin-template-provider.toml` |

---

## 9. Confirm AZCoin Core RPC readiness

The templar relies on **`azcoind`** JSON-RPC (not ZMQ for templates in this service).

```bash
sudo systemctl is-active azcoind.service

sudo journalctl -u azcoin-template-provider.service --since "15 minutes ago" --no-pager | \
  grep -E 'event=rpc_connectivity_ready|event=azcoin_rpc_error|getblocktemplate' || true

# Manual RPC smoke if you have CLI access (NO secrets in commands — use your local azc/bitcoin-cli wrapper)
# Example pattern only — substitute your site’s RPC client and omit passwords from shell history:
#   <rpc-client> getblockchaininfo | jq '{chain, blocks, verificationprogress}'
```

Signs of problems:

- Repeating `event=azcoin_rpc_error` with `method=getblocktemplate` or connectivity messages.
- `AZCoin Core chain mismatch` messages at startup (node `chain` is not **main**).

Restart order when debugging: **`azcoind` stable first**, then **templar**, then reassess pool.

---

## 10. Confirm pool connection

Operational signs:

```bash
sudo journalctl -u azcoin-template-provider.service --since "15 minutes ago" --no-pager | \
  grep -E 'event=pool_connected|event=pool_disconnected|authority public key|listening' || true

sudo systemctl is-active pool-sv2.service
```

- **`event=pool_connected`** after Noise + `SetupConnectionSuccess` implies the pool reached Template Distribution handshake.
- Frequent **`event=pool_disconnected`** without restarts warrants checking network/firewall/timeouts and pool logs (`pool-sv2.service`).
- Noise **authority public key** is logged at startup for cross-check against pool config (`pool_sv2` SV2 TP trust settings).

---

## 11. Confirm templates are flowing

Use structured events (default `INFO` emphasizes `event=`).

```bash
sudo journalctl -u azcoin-template-provider.service --since "10 minutes ago" --no-pager | \
  grep -E 'event=(template_loaded|template_changed|template_sent)' || true
```

Interpretation sketch:

| Event | Rough meaning |
|-------|----------------|
| `template_loaded` | First tracked template/`template_id` from poller |
| `template_changed` | GBT materially changed vs prior snapshot |
| `template_sent` | Pair `NewTemplate` + `SetNewPrevHash` written to SV2 |

If **`template_sent` is absent** while GBT succeeds:

- Confirm SV2 Noise keys configured (poller-only mode disables listener).
- Check pool connectivity (section 10) and **`CoinbaseOutputConstraints`** gate warnings.

---

## 12. Inspect SubmitSolution / submitblock events

Expected happy path sequence (names only — exact wording may vary slightly by build):

```
event=solution_received
event=submitblock_called
event=submitblock_result  (with outcome accepted, or rejection reason string)
```

```bash
sudo journalctl -u azcoin-template-provider.service --since "1 hour ago" --no-pager | \
  grep -E 'event=(solution_received|submitblock_called|submitblock_result)' || true

# Cross-check RPC-side rejections correlate with templar logs
sudo journalctl -u azcoin-template-provider.service --since "1 hour ago" --no-pager | \
  grep -E 'reject_reason|outcome=rejected_by_node|outcome=rpc_' || true
```

**Reminder:** payouts and ledger truth live **outside** the Template Provider — a successful **`submitblock`** only means the node accepted the block proposition per RPC semantics.

---

## 13. Common failure cases and first commands to run

| Symptom | First commands |
|---------|----------------|
| Unit fails on boot | `sudo systemctl status azcoin-template-provider.service -l --no-pager` · `journalctl -u azcoin-template-provider.service -b --no-pager` |
| “AZCoin Core chain mismatch” | Confirm `getblockchaininfo.chain` is **main** on the node this provider targets |
| RPC / HTTP errors (`event=azcoin_rpc_error`) | Confirm `rpc_url`, credentials match **azcoind** (without logging secrets); confirm `azcoind` listens on expected bind |
| No `pool_connected` | Check `pool-sv2.service` · templar listens on `tp_listen_address` · firewall · Noise keys |
| Stale templates / Lagged warnings | See main README troubleshooting; increase resilience via poll tuning / infra load review |
| `submitblock_result` rejects | Read `reject_reason` / outcome; inspect node logs; verify pool used correct template work |
| Assembly failures | Logs with `outcome=block_assembly_failed` — usually template cache / malformed solution path |

Grab a tight recent slice:

```bash
sudo journalctl -u azcoin-template-provider.service -n 300 --no-pager
sudo journalctl -u pool-sv2.service -n 200 --no-pager
```

---

## 14. Security notes

- **Never** paste live RPC passwords, cookies, Bearer tokens, or Noise private keys into chat, markdown, or shared terminals with history enabled.
- Protect `/etc/azcoin-super/templar/azcoin-template-provider.toml` with tight filesystem permissions (`640`/`600` typical; owned by root or dedicated ops user per your policy).
- The Template Provider is **not** a wallet host — treat RPC access like production infrastructure: firewall, localhost-only where possible, or TLS + network ACLs per site standards.
- Redact journals and support bundles before exporting externally.
- The service user **`azcoin-templar`** should have least privilege — only what is needed for the binary, config readability, and any configured state under `/var/lib/azcoin-super/templar`.
- ZMQ Publisher sockets (`rawtx` / `hashblock` / `sequence`) are typically **unauthenticated** — bind AZCoin Core publishers to **loopback** or operator-trusted internal interfaces; templar Subscribes to all three (**payloads discarded for template assembly**).

---

## AZCoin Core JSON-RPC allowlist (`rpcwhitelist` reference)

**Required** during normal mining operation (steady-state templar invokes these today):

| Method |
|--------|
| `getblockchaininfo` |
| `getblocktemplate` |
| `submitblock` |

**Optional / internal diagnostics** (`src/rpc.rs` defines helpers that are **not** called by `main` today — tooling only):

| Method | Note |
|--------|------|
| `getbestblockhash` | Correct Bitcoin/Core name — **`getbesthash` is invalid** |
| `getblockheader` | Verbose header diagnostic |

Restrict other RPC namespaces from production mining credentials wherever possible.

## ZMQ-first template wakeup (`rawtx` / `hashblock` / `sequence`)

Templar **always** launches a Subscriber that **connects to all three configured endpoints** (`zmq_endpoint_*` keys) and subscribes to **`rawtx`**, **`hashblock`**, and **`sequence`**.

- **hashblock wake** — maps to fastest “new tip” refreshes (**SV2 broadcasts always on prevhash / height rollover** versus last pushed template — **never blocked by fee delta or txn cap**).
- **rawtx / sequence wake** — additional mempool / ordering hints (**SV2 broadcast only after `getblocktemplate` shows same tip**, fee delta **`≥ fee_threshold`**, and **`transactions.len() ≤ max_template_transactions`**).

Every wakeup triggers **`getblocktemplate`** RPC (still **authoritative**). **`poll_interval_ms`** timers never stop (**perpetual safety fallback**).

**AZCoin Core** (example — ports must mirror per-topic `zmq_endpoint_*` in templar):

```text
zmqpubrawtx=tcp://127.0.0.1:29333
zmqpubhashblock=tcp://127.0.0.1:29334
zmqpubsequence=tcp://127.0.0.1:29335
```

**Template Provider TOML** (`config/azcoin-template-provider.toml.example` — see its **header comments** for CLI flags, RPC/ZMQ reference, and compiled constants): set `zmq_endpoint_rawtx`, `zmq_endpoint_hashblock`, `zmq_endpoint_sequence`, plus `fee_threshold`, `max_template_transactions`, timeouts/debounce, and optional **`log_file`** (**parent directory must pre-exist**, writable only by the service user).

Legacy **`zmq_enabled`** / **`zmq_endpoint`** / per-topic booleans **do not change today's wiring** — they are ignored if present — ZMQ wakeup is unconditional.

Tune **`poll_interval_ms` slower when ZMQ + node are healthy** — ZMQ absorbs bursty mempool/tip chatter while polls remain the failsafe (`event=zmq_error` includes **`polling_fallback_active=true`**). **`event=template_refresh_trigger`** emits at **`DEBUG`** with `reason` ∈ {`poll`, `zmq_rawtx`, `zmq_hashblock`, `zmq_sequence`} (raise `RUST_LOG` when diagnosing).

**Operational smoke:**

```bash
azcoin-cli getzmqnotifications

sudo journalctl -u azcoin-template-provider.service -n 320 --no-pager -l \
  | grep -E 'event="zmq_(subscriber_starting|subscriber_ready)"|event="template_refresh_trigger"' \
  || true
```

---

## 15. Block submission audit

Template Provider is the owned integration point between AZCoin Core and the SV2 pool path. Treat **`sv2-apps` / `pool_sv2`** as **external software** — it may run on a **different host** from Template Provider — and do **not** patch it for audit visibility unless AZCOIN deliberately forks or vendors it. This service already logs the **authoritative block-submission lifecycle** (`event=` fields) whether a **local or remote** pool client submits a solution over the SV2 connection.

Relevant lifecycle events:

- `event="solution_received"`
- `event="submitblock_called"`
- `event="submitblock_result"`

An **accepted block** record in the journal corresponds to **`event="submitblock_result"`** lines that also include **`outcome="accepted"`**, **`accepted=true`**, **`template_id`**, and **`block_hash`**.

**Where to run (deployment scope)**

- Run the **`journalctl`** snippets below and **`scripts/block_submission_audit.sh`** on the host that runs **`azcoin-template-provider.service`** — i.e. the **Template Provider / AZCoin Core** side — **not** where **`pool_sv2`** happens to run.
- This audit uses **only** **`azcoin-template-provider.service`** journals. It **must not** assume or require any of the following **on that host**: **`pool-sv2.service`** (or any local pool unit), **local pool `journalctl`** / pool journal files, a checkout of **`sv2-apps`**, **pool config files**, or **paths to a local pool binary**.
- When present on a line, **`peer=`** is the **SV2 client endpoint as seen by Template Provider** (often **loopback today** if **`pool_sv2`** is colocated; **may later be a remote pool IP/socket** when deployments split roles across hosts). Use it to correlate which peer produced a given lifecycle line — not for payout/accounting truth.

Copy/paste (adjust `--since`/line counts if needed):

**1. Full solution / submission lifecycle**

```bash
sudo journalctl -u azcoin-template-provider.service -n 1000 --no-pager -l \
  | grep -E 'event="solution_received"|event="submitblock_called"|event="submitblock_result"'
```

**2. Accepted blocks only**

```bash
sudo journalctl -u azcoin-template-provider.service -n 2000 --no-pager -l \
  | grep 'event="submitblock_result"' \
  | grep 'accepted=true'
```

**3. Optional: recent accepted block hashes (`template_id` + `block_hash`)**

```bash
sudo journalctl -u azcoin-template-provider.service -n 2000 --no-pager -l \
  | grep 'event="submitblock_result"' \
  | grep 'accepted=true' \
  | sed -n 's/.*template_id=\([0-9]*\).*block_hash=Some("\([^"]*\)").*/template_id=\1 block_hash=\2/p'
```

**Helper script (`scripts/block_submission_audit.sh`)**

Same filters as examples 2–3, with a stable text or JSON Lines printout (no `jq` / Python — `awk` only). **Execute on the Template Provider / AZCoin Core host** (adjust path as needed). It invokes **`sudo journalctl -u azcoin-template-provider.service`** only — identical non-dependencies as above (**no** **`pool-sv2.service`**, pool journald, **`sv2-apps`**, pool configs, or pool binaries on this machine).

```bash
scripts/block_submission_audit.sh

scripts/block_submission_audit.sh --lines 5000

scripts/block_submission_audit.sh --since "2026-05-07 00:00:00"

scripts/block_submission_audit.sh --since "today" --jsonl
```

**How to interpret these logs**

- The **journal timestamp** is when Template Provider observed each step — treat it as the **observed submission / acceptance time**, not a chain timestamp.
- **`block_hash`** is the **candidate / submitted block hash** Template Provider logs around **`submitblock`** (before and after the RPC), not third-party pool accounting.
- When **`peer=`** appears on a log line, it is **Template Provider’s view of the pool client endpoint** for that lifecycle event (often **localhost / loopback** today when the pool is colocated; may later be a **remote pool IP or socket** when roles are split across hosts). Use it to correlate which peer produced the line **without** local pool journald here — **`peer=`** is still **not** miner payout or ledger truth (`peer=` ≠ miner identity ledger).
- **`accepted=true`** means AZCoin Core’s **`submitblock`** returned **`null`**, which in Bitcoin-style RPC semantics means the node **accepted** the block.
- This trail is **operational auditing** (“what did we submit, what did the node say?”). It is **not** miner **payout** or ledger **truth** — that lives in your pool/payout stack.
- **Do not use `coinbase_output_count`** in logs as payout truth — it reflects SV2/template construction metadata, not payout policy (see section 2).

---

## Related documentation

- Repository **README.md** — scope, structured log field reference (`event=`), developer build/run.
