git status
git add -A
git commit -m "Bug fixes and stale block error fixes to v0.1.5"   
git tag v0.1.5
git push origin main
git push origin v0.1.5

$SHA = (git rev-parse --short HEAD).Trim()

# Build once, tag many (v0.1.4 + stable + sha; optionally latest)
$SHA = (git rev-parse --short HEAD).Trim()