# Poly Bridge Case Study (fixed)

Run locally (PowerShell/CMD):

```bash
# in project root
npm install
npx hardhat compile
npx hardhat test

# run demonstration scripts
npx hardhat run scripts/exploit.js
npx hardhat run scripts/exploit_patched.js
