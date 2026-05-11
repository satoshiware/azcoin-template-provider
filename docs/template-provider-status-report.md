# AZCOIN Template Provider — program status & testing report

**Audience:** Mike / CEO / technical leadership  
**Date context:** reflects the current codebase and super-node **AZCOIN SV2 Template Provider** milestone; scope is **complete for this product boundary**, not “mining stack finished forever.”

---

## 1. Executive summary

The **Template Provider** delivers a **production-style** path between **AZCoin Core** and **external** SV2 pools (`pool_sv2` / sv2-apps): authoritative **`getblocktemplate`**, **`submitblock`**, **ZMQ-first** refresh with **polling fallback**, **Noise-authenticated** Template Distribution, and **structured operational logs**. **Super-node deployment (Profile A)** and an **alternative CEO/standalone layout (Profile B)** are **documented**; **payout, share accounting, and pool business logic remain outside this repository.**

**Live verification** on at least one super-node host shows the service **running**, ZMQ **connected**, template **refresh and push** behavior, **multiple remote pool peers** receiving work, and the **block submission audit** helper behaving as designed.

**Before calling a release “done,”** engineering must still run through **packaging, checksums, install smoke, `--health-check`, ZMQ/Core alignment checks, rollback documentation**, and **post-install template/audit verification** on representative hosts.

---

## 2. Current status

| Dimension | State |
|-----------|--------|
| Core product (GBT + submitblock + SV2 TD + ZMQ + poller policy) | **Implemented and CI-green** for the current milestone |
| Documentation (runbook, deployment profiles, ZMQ naming, example config) | **In repo**; example config should be **frozen as release artifact** |
| Super-node fleet alignment | **Profile A documented** as current live standard |
| External pool software | **Explicitly out of scope** — `pool_sv2` is not owned or shipped here |
| Release hygiene (version tag, tarball, staging install matrix) | **Not complete** until checklist below is executed |

---

## 3. Completed scope

- **Deployment alignment:** Profile A super-node layout in docs (`azcoin-templar`, `/opt/azcoin-super/templar/…`, `/etc/azcoin-super/templar/azcoin-template-provider.toml`, `/var/lib/azcoin-super/templar`). Profile B (CEO/standalone) documented as **alternative**.
- **Template truth:** **`getblocktemplate`** over JSON-RPC is **authoritative**; ZMQ is **wakeup-only**.
- **Submission path:** **`submitblock`** over JSON-RPC after **`SubmitSolution`** assembly.
- **ZMQ:** Subscriber connects to configured endpoints; topics **rawtx / hashblock / sequence**; **ZMQ-first** update policy with **slower `poll_interval_ms` fallback**.
- **Policy:** Hardcoded **AZCOIN `main`** chain check; **`["segwit"]`** GBT rules in binary.
- **Observability:** **`event=`** structured logs; **`peer=`** for correlating SV2 clients (audit, not payout ledger).
- **Fan-out:** Design supports **multiple simultaneous SV2 peers** (remote pools); not an endorsement of unlimited trust—that is **hardening** (see wishlist).
- **Operations:** [Operational runbook](template-provider-runbook.md), deployment profile + **ZMQ naming contract** in README/runbook, example TOML header comments.
- **Audit tooling:** `scripts/block_submission_audit.sh` for submission lifecycle review **from templar journals**.

**Explicit non-scope:** This service does **not** implement miner **payout**, **accounting truth**, or **pool_sv2** itself. **`coinbase_output_count`** in logs is **SV2/template construction metadata**, **not** payout truth.

---

## 4. Testing performed (repository / CI)

| Check | Role |
|--------|------|
| `cargo fmt --check` | Format consistency |
| `cargo test` | Unit and module tests (config, RPC, template, poller policy, ZMQ classification, tp_server helpers, etc.) |
| `cargo clippy --all-targets -- -D warnings` | Lint gate |
| `cargo build --release` | Release artifact build |
| `bash -n scripts/block_submission_audit.sh` | Audit script syntax |
| `git diff --check` | Whitespace / patch hygiene |

These validate **code health and in-repo behavior**, not full multi-datacenter integration.

---

## 5. Live verification evidence (super-node host)

**Host reference:** `partyintheback01` (representative super-node). **Evidence types:** service state, logs, network observability—not financial ledger proof.

Observed:

- Service **active/running** after deployment work.
- ZMQ subscriber **starts** and **connects** to per-site endpoints, e.g.:
  - **rawtx** `tcp://127.0.0.1:29335`
  - **hashblock** `tcp://127.0.0.1:29332`
  - **sequence** `tcp://127.0.0.1:29336`
- Logged refresh reasons including **`zmq_hashblock`** and **`poll`** (fallback).
- **`template_changed`**, **`template_sent`** events present.
- **Multiple remote pool-side peers** observed receiving templates (e.g. `10.10.70.131`, `10.10.70.43`; previously `10.10.80.10`) — demonstrates **multi-peer / remote fan-out** capability; **not** a statement about payout or miner identity.
- **`scripts/block_submission_audit.sh`**: text and JSONL output **verified** on operator workflows.

---

## 6. Must-do before release / production cutover

- **Finalize** `config/azcoin-template-provider.toml.example` as the **release** example (no live secrets).
- **Confirm** release **version / tag naming** and changelog alignment with binaries.
- **Build** release binary **from tagged commit**.
- **Package** artifact **(tarball or org-standard layout)** + **checksum** file.
- **Test install/update path** on a **staging** or **target-class** host (permissions, paths, systemd).
- Run **`--health-check`** with the **same config** that will ship.
- **Verify AZCoin Core** `zmqpub*` binds **match** Template Provider **`zmq_endpoint_*`** (per-site ports).
- **Restart** from **packaged** binary; confirm **`template_changed` / `template_sent`** resume.
- Re-run **audit helper** against fresh journals post-restart.
- **Document rollback**: prior binary path, config backup path, `systemctl` restart order.
- **Operator sign-off** on README/runbook pointers for the **tagged** docs revision.

---

## 7. Wishlist / future hardening

- **Connection policy:** configurable limits / allowlist for SV2 peers (trust boundary).
- **Metrics:** active peers, broadcast depth, lag / backpressure visibility (Prometheus-style or journal-driven).
- **Testing:** **two-pool** or **multi-peer** automated integration test (hermetic, no production keys).
- **Persistence:** optional DB or shipper for **accepted block** events (ops analytics—not payout).
- **Installer:** if **Profile B** becomes fleet default, formal **migration** from Profile A.
- **Automation:** release packaging, signing, checksum publication pipeline.
- **Central logging:** aggregation / dashboards for `event=` fields.
- **RPC deployment:** formal **`rpcwhitelist`** rollout doc + Core config parity review.

---

## 8. Risks / assumptions

- **External pool** and **translator** stacks can fail independently; Template Provider correctness does not imply **downstream** health.
- **ZMQ** and **RPC** are **best-effort** from an ops perspective; **polling** mitigates missed ZMQ events but adds latency.
- **Remote peers** increase **attack surface** and **support variance** unless network and auth policies are tightened (wishlist).
- **Release checklist** not run on every fork/host OS—**staging** validation remains mandatory.

---

## 9. Recommendation

**Approve the Template Provider milestone as “feature-complete for the documented scope,”** contingent on **executing the release checklist** (artifacts, checksums, install smoke, `--health-check`, ZMQ parity, rollback doc) and **tagging documentation** to match the release. Treat **payout, pool product, and sv2-apps** as **separate programs** with their own release gates.

---

## Related documentation

- [Template Provider runbook](template-provider-runbook.md)  
- Repository [README](../README.md) — deployment profiles, ZMQ contract, build/test commands
