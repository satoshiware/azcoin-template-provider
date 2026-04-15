git status
git add -A
git commit -m "v0.1.7-r1: revision 1"
git tag v0.1.7-r1
git push origin main
git push origin v0.1.7-r1

$SHA = (git rev-parse --short HEAD).Trim()

# revision 1
