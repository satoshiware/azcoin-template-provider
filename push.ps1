git status
git add -A
git commit -m "Adding logs and updating to v0.1.4"   
git tag v0.1.4
git push origin main
git push origin v0.1.4

$SHA = (git rev-parse --short HEAD).Trim()

# Build once, tag many (v0.1.4 + stable + sha; optionally latest)
$SHA = (git rev-parse --short HEAD).Trim()