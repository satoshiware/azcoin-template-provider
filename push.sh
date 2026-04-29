#!/usr/bin/env bash
# Linux/macOS equivalent of push.ps1 (PowerShell). From repo root: ./push.sh
set -euo pipefail

git status
git add -A
git commit -m "v0.2.0 — stable SV2 Template Provider release"
git tag v0.2.0
git push origin main
git push origin v0.2.0

SHA="$(git rev-parse --short HEAD)"
echo "$SHA"
