# Template Provider — release checklist & dry-run plan

Use this document for **cutting a release** and for a **dry run** (no tag required). It assumes the **Profile A** super-node layout unless noted; see [deployment profiles in README](../README.md#deployment-profiles).

**Related:** [Program status & testing](template-provider-status-report.md) · [Operational runbook](template-provider-runbook.md)

---

## 1. Release version decision

- [ ] Confirm **SemVer** bump vs last tag (e.g. patch for docs-only, minor for behavior, major for breaking config or wire protocol).
- [ ] Align **crate version** in `Cargo.toml` with the **git tag** you will create at release time (this checklist does not create the tag).
- [ ] Record **release notes** scope: ZMQ-first template policy, ZMQ-triggered refresh, polling fallback, block audit helper, docs/runbook, example config, status report.

---

## 2. Pre-release checks

Run from a **clean working tree** on the release commit (adjust branch name):

```bash
cd /path/to/azcoin-template-provider

git status --short
git log --oneline -5

cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
bash -n scripts/block_submission_audit.sh
```

- [ ] `git status --short` shows **no unexpected changes** (or only intentional release-prep edits).
- [ ] `Cargo.lock` committed if `Cargo.toml` dependencies changed (project policy).
- [ ] **Example config** reviewed: `config/azcoin-template-provider.toml.example` (no live secrets; placeholders only).
- [ ] **Docs** present: runbook, status report, deployment/ZMQ contract sections in README as applicable.
- [ ] **No live secrets** in repo (no copies of `/etc/...` production files with real passwords).

---

## 3. Build commands

```bash
cargo build --release
```

Artifact (typical):

`target/release/azcoin-template-provider`

- [ ] Build completes **without warnings** under the clippy gate above.
- [ ] Optional: run `strip` only if your distribution policy allows it (not documented here by default).

---

## 4. Artifact layout

Convention for a portable drop (names are examples—adjust version):

```text
azcoin-template-provider-0.2.x/
├── bin/azcoin-template-provider    # release binary from target/release/
├── config/azcoin-template-provider.toml.example
├── docs/                            # optional: subset or symlink to repo docs
├── scripts/block_submission_audit.sh
└── README.md                        # optional copy for offline reading
```

- [ ] Decide whether the tarball includes **full `docs/`** or only **runbook + status + checklist** to limit size.
- [ ] **Never** bundle `config/azcoin-template-provider.toml` with real credentials.

---

## 5. Checksum command

After creating the `.tar.gz` (see §6):

```bash
sha256sum azcoin-template-provider-0.2.x-linux-x86_64.tar.gz > azcoin-template-provider-0.2.x-linux-x86_64.tar.gz.sha256
cat azcoin-template-provider-0.2.x-linux-x86_64.tar.gz.sha256
```

- [ ] Publish **`sha256` alongside the tarball** on the GitHub Release (or internal artifact store).
- [ ] Verify on a second machine: `sha256sum -c *.sha256`.

---

## 6. Smoke test commands

**Binary smoke (after build):**

```bash
./target/release/azcoin-template-provider --help
./target/release/azcoin-template-provider --health-check --config /path/to/your/azcoin-template-provider.toml
```

Use a **test** or **staging** config that points at a safe node; **do not** use production secrets in CI logs.

- [ ] `--health-check` exits **0** (RPC + `main` chain as implemented).
- [ ] Optional: start full service briefly in a VM with staging `azcoin.conf` ZMQ aligned to `zmq_endpoint_*`.

**Tarball dry-run:**

```bash
tar -tzf azcoin-template-provider-0.2.x-linux-x86_64.tar.gz | head
```

**Audit script:**

```bash
bash -n scripts/block_submission_audit.sh
```

---

## 7. Install / update commands (Profile A super-node layout)

Paths (typical):

| Item | Path |
|------|------|
| Binary | `/opt/azcoin-super/templar/bin/azcoin-template-provider` |
| Config | `/etc/azcoin-super/templar/azcoin-template-provider.toml` |
| User | `azcoin-templar` |

**Install or replace binary (example):**

```bash
sudo install -o root -g root -m 0755 \
  ./target/release/azcoin-template-provider \
  /opt/azcoin-super/templar/bin/azcoin-template-provider
```

**Merge new example keys** into live config (do not blindly overwrite secrets):

```bash
sudo diff -u /etc/azcoin-super/templar/azcoin-template-provider.toml \
  /path/to/new/azcoin-template-provider.toml.example || true
# edit live config, then:

sudo systemctl restart azcoin-template-provider.service
sudo systemctl status azcoin-template-provider.service --no-pager
```

- [ ] **`--health-check`** with **final** config before restart.
- [ ] After restart, confirm **`template_changed` / `template_sent`** and ZMQ connectivity in logs.

---

## 8. Rollback commands

```bash
# Example: restore prior binary if kept beside live path
sudo install -o root -g root -m 0755 \
  /opt/azcoin-super/templar/bin/azcoin-template-provider.bak.<TIMESTAMP> \
  /opt/azcoin-super/templar/bin/azcoin-template-provider

sudo systemctl restart azcoin-template-provider.service
```

- [ ] **Document** your site’s **known-good backup path** and **config backup** (e.g. `.bak` copy in `/etc/azcoin-super/templar/`).

---

## 9. GitHub release steps

- [ ] **Tag** on the release commit (operators run `git tag -a v0.2.x -m "..."` per project policy—not executed by this file).
- [ ] Push tag: `git push origin v0.2.x`
- [ ] **GitHub Releases** → Draft → attach **`tar.gz`** + **`.sha256`**
- [ ] Paste **release notes** (link runbook, status report, checklist).
- [ ] Confirm **default branch** README points to current docs for users who clone instead of downloading the tarball.

---

## 10. sc-node/azpool/templar copy experiment (exploratory)

**Intent:** Explore mirroring this repository into another tree (e.g. organizational monorepo path) **without** overwriting work-in-progress.

**Rules:**

- **Exploratory** unless product owners promote it to the canonical location.
- **Do not** overwrite existing directories without inspection.
- **Timestamped backup** if destination already exists.
- **Do not copy secrets**: exclude local credentialed configs, `**/azcoin-template-provider.toml` (non-example), `.env`, etc.
- **Do not** import `/etc` live configs into the repo.

**Inspect destination first:**

```bash
ls -la /path/to/sc-node/azpool/ 2>/dev/null || true
ls -la /path/to/sc-node/azpool/templar 2>/dev/null || true
```

**Optional: timestamped backup of existing destination:**

```bash
DEST=/path/to/sc-node/azpool/templar
if [ -e "$DEST" ]; then
  sudo mv "$DEST" "${DEST}.bak.$(date +%Y%m%d-%H%M%S)"
fi
```

**rsync from repo root (adjust SRC):**

```bash
SRC=/path/to/azcoin-template-provider
DEST=/path/to/sc-node/azpool/templar

rsync -a --delete \
  --exclude '.git/' \
  --exclude 'target/' \
  --exclude '.env' \
  --exclude 'config/azcoin-template-provider.toml' \
  --exclude '*.pem' \
  "$SRC/" "$DEST/"
```

- [ ] Re-run **`cargo test`** / **`cargo build --release`** from **`$DEST`** after copy if that tree becomes authoritative.
- [ ] Decide **whether `.git` should be recreated** (fresh `git init` in monorepo) vs submodule—**product decision**.

---

## 11. Release acceptance criteria

- [ ] All **§2 Pre-release checks** green on the exact **release commit**.
- [ ] **Release binary** built with **`cargo build --release`** and smoke-tested (**`--help`**, **`--health-check`**).
- [ ] **Artifact + sha256** produced and verified off-box.
- [ ] **Profile A** install path tested on **staging** or **one** production-class host (or dry-run documented).
- [ ] **ZMQ** `zmqpub*` on AZCoin Core **match** Template Provider **`zmq_endpoint_*`** on that host.
- [ ] **`scripts/block_submission_audit.sh`** syntax-checked and run against sample logs.
- [ ] **Docs** shipped with artifact or linked from tag: runbook, status report, **this checklist**, example config.
- [ ] **Rollback** path documented for operators.
- [ ] **No claim** that Template Provider solves **payout/accounting**; **pool_sv2** remains **external**.

---

## Appendix: tarball creation (example)

**Not executed as part of this documentation task**—run locally when packaging:

```bash
VERSION=0.2.x
D=azcoin-template-provider-${VERSION}-linux-x86_64
mkdir -p "$D/bin" "$D/config" "$D/scripts"
install -m 0755 target/release/azcoin-template-provider "$D/bin/"
install -m 0644 config/azcoin-template-provider.toml.example "$D/config/"
install -m 0755 scripts/block_submission_audit.sh "$D/scripts/"
# optional: cp -r docs "$D/"  (trim if needed)

tar -czvf "${D}.tar.gz" "$D"
sha256sum "${D}.tar.gz" > "${D}.tar.gz.sha256"
```

Replace `VERSION` and add `docs/README` copies per §4.
