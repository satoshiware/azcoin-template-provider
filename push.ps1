git status
git add -A
git commit -m "Finalizing the first version of azcoin-template-provider fixed 2 mismatches with the reference implementation v0.1.0"   
git tag v0.1.0
git push origin main
git push origin v0.1.0

$SHA = (git rev-parse --short HEAD).Trim()

# Build once, tag many (v0.1.4 + stable + sha; optionally latest)
$SHA = (git rev-parse --short HEAD).Trim()