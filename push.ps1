git status
git add -A
git commit -m "v0.2.0: stable SV2 mining baseline Template Provider"
git tag v0.2.0
git push origin main
git push origin v0.2.0

$SHA = (git rev-parse --short HEAD).Trim()

# AZCOIN Template Provider 0.2.0 — live templates, SubmitSolution, submitblock
