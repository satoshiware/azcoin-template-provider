git status
git add -A
git commit -m "v0.1.6: fixed coinbase height bug and unexpected-witness bug"
git tag v0.1.6
git push origin main
git push origin v0.1.6

$SHA = (git rev-parse --short HEAD).Trim()

# fixed coinbase height bug and unexpected-witness bug
