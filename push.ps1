# Windows PowerShell helper. On Linux/macOS, use ./push.sh instead.
git status
git add -A
git commit -m "v0.2.0 — stable SV2 Template Provider release"
git tag v0.2.0
git push origin main
git push origin v0.2.0

$SHA = (git rev-parse --short HEAD).Trim()