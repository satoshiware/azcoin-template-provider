# AZCoin Template Provider — operational runbook

Linux-oriented procedures for the **super-node** Template Provider deployment. This document is **reference only** for operators; it does not configure your host.

---

## 1. Purpose

The AZCoin Template Provider is the super-node service that:

- Pulls mining block templates from AZCoin Core (`getblocktemplate` over JSON-RPC).
- Serves templates to the local (or remote) SV2 pool over **Stratum V2 Template Distribution** (Noise + `NewTemplate` / `SetNewPrevHash`).
- Accepts `SubmitSolution` from the pool, assembles a full block, and submits it via **`submitblock`** on the node.

It is the authoritative **template + block-submission gateway** for that mining path. It does **not** replace AZCoin Core, the pool, or payout infrastructure.

---

## 2. Architecture role / non-goals

**In scope**

- Template freshness (polling + live roll-forward to the pool).
- Correct SV2 template identity (`template_id` caching).
- Forwarding solved blocks to the node RPC.

**Explicit non-goals (do not expect this service to)**

- Calculate miner payouts, splits, or balances.
- Perform SC-node or per-worker accounting.
- Hold or manage private keys, seeds, wallets, or custody.
- Interpret `coinbase_output_count` in logs as “how many payouts” — it reflects **SV2 placeholder / construction** metadata, **not** payout policy truth.

Operators own payout logic, wallet policy, and pool configuration elsewhere.

---

## 3. Key paths and service names

| Item | Path or name |
|------|----------------|
| systemd unit | `azcoin-template-provider.service` |
| Live binary | `/opt/azcoin-super/templar/bin/azcoin-template-provider` |
| Live config (TOML) | `/etc/azcoin-super/templar/azcoin-template-provider.toml` |
| Service user | `azcoin-templar` |
| Runtime state (typical layout) | `/var/lib/azcoin-super/templar` |
| Logs (site-specific; often journald) | `/var/log/azcoin-super/templar` (if redirected); default is often **`journalctl`** |
| Related: AZCoin Core | `azcoind.service` |
| Related: SV2 pool | `pool-sv2.service` |

**Source/build workspace** (developer checkout) is separate from these paths unless you deliberately install into `/opt`.

---

## 4. Five-minute health verification checklist

Run in order; all should look sane before declaring “healthy.”

1. **Units up** — `azcoin-template-provider`, `azcoind`, and `pool-sv2` show `active (running)` where expected.
2. **No restart storm** — `systemctl status` shows low restart count / recent uptime unless you intentionally restarted.
3. **Structured events** — last few minutes include `event=template_provider_startup`, `event=rpc_connectivity_ready`, and (if SV2 enabled) `event=pool_connected` / `event=template_sent`.
4. **Core RPC** — node responds (`getblockchaininfo` matches configured `network` in TOML; not stuck in unexpected error loops in templar logs).
5. **No critical error bursts** — `journalctl -p err` for the templar unit is quiet aside from known maintenance windows.

Copy/paste starters:

```bash
sudo systemctl is-active azcoind.service pool-sv2.service azcoin-template-provider.service

sudo systemctl status azcoin-template-provider.service --no-pager -l | head -n 25

sudo journalctl -u azcoin-template-provider.service --since "10 minutes ago" --no-pager | grep -E 'event=(template_provider_startup|rpc_connectivity_ready|pool_connected|template_sent|submitblock_)' || true
```

---

## 5. Runtime health-check command

The binary supports a **one-shot** RPC and config validation (**no listener**, **no poller**) suitable for probes:

```bash
sudo -u azcoin-templar /opt/azcoin-super/templar/bin/azcoin-template-provider \
  --health-check \
  --config /etc/azcoin-super/templar/azcoin-template-provider.toml
```

- Exit **0** means config loaded and JSON-RPC/`network` checks passed.
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
- `network mismatch` messages at startup (config `network` vs node `chain`).

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
| “Network mismatch” | Compare TOML `network` vs `getblockchaininfo.chain` (via your RPC tooling) |
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

---

## Related documentation

- Repository **README.md** — scope, structured log field reference (`event=`), developer build/run.
