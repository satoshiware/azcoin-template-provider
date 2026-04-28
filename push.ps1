git status
git add -A
git commit -m "v0.2.0-r1 (fix) adding additional capabilities to the template provider"
git tag v0.2.0-r1
git push origin main
git push origin v0.2.0-r1

$SHA = (git rev-parse --short HEAD).Trim()