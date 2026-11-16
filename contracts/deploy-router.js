/**
 * PearlFeeRouter Multi-Chain EVM Deployment Helper (Scheme B)
 *
 * Usage:
 *   1. Compile `contracts/PearlFeeRouter.sol` (e.g. via `solc --combined-json abi,bin` or Foundry/Hardhat)
 *      and save `{ abi, bytecode }` to `contracts/PearlFeeRouter.artifact.json`.
 *   2. Run with a funded deployer key:
 *      DEPLOYER_PRIVATE_KEY=0x... node contracts/deploy-router.js base
 *      (Supported chains: eth, base, bsc, arb, hood)
 */
const fs = require('fs');
const path = require('path');
const { ethers } = require(path.join(__dirname, '..', 'ethers.umd.min.js'));

const CHAINS = {
  eth:  { chainId: 1,     rpc: 'https://ethereum-rpc.publicnode.com',         name: 'Ethereum' },
  base: { chainId: 8453,  rpc: 'https://mainnet.base.org',                    name: 'Base' },
  bsc:  { chainId: 56,    rpc: 'https://bsc-dataseed.bnbchain.org',           name: 'BSC' },
  arb:  { chainId: 42161, rpc: 'https://arb1.arbitrum.io/rpc',                name: 'Arbitrum' },
  hood: { chainId: 4663,  rpc: 'https://rpc.mainnet.chain.robinhood.com',     name: 'Robinhood Chain' }
};

const FEE_RECEIVER = '0x00dCBFDe63933Dc710Dd804dE58602d267BCCE34';
const FEE_BPS = 25; // 0.25%

// Standard KyberSwap MetaAggregationRouterV2 & ParaSwap Augustus V6 addresses
const DEFAULT_ROUTERS = [
  '0x6131B5fae19EA4f9D964eAc0408E4408b66337b5', // KyberSwap MetaAggregationRouterV2
  '0x6A000F20005980200259B80c5102003040001068'  // ParaSwap Augustus v6.2
];

async function main() {
  const chainKey = (process.argv[2] || '').toLowerCase();
  const cfg = CHAINS[chainKey];
  if (!cfg) {
    console.error(`Usage: DEPLOYER_PRIVATE_KEY=0x... node contracts/deploy-router.js <${Object.keys(CHAINS).join('|')}>`);
    process.exit(1);
  }
  const pk = process.env.DEPLOYER_PRIVATE_KEY;
  if (!pk) {
    console.error('Missing DEPLOYER_PRIVATE_KEY env var.');
    process.exit(1);
  }
  const artifactPath = path.join(__dirname, 'PearlFeeRouter.artifact.json');
  if (!fs.existsSync(artifactPath)) {
    console.error(`Missing ${artifactPath}. Compile PearlFeeRouter.sol first (see contracts/README.md).`);
    process.exit(1);
  }
  const artifact = JSON.parse(fs.readFileSync(artifactPath, 'utf8'));
  const provider = new ethers.JsonRpcProvider(cfg.rpc, cfg.chainId);
  const wallet = new ethers.Wallet(pk, provider);
  console.log(`Deploying PearlFeeRouter to ${cfg.name} (${cfg.chainId}) from ${wallet.address}...`);

  const factory = new ethers.ContractFactory(artifact.abi, artifact.bytecode, wallet);
  const contract = await factory.deploy(FEE_RECEIVER, FEE_BPS, DEFAULT_ROUTERS);
  console.log('Tx hash:', contract.deploymentTransaction().hash);
  await contract.waitForDeployment();
  const addr = await contract.getAddress();
  console.log(`✅ Deployed PearlFeeRouter on ${cfg.name}: ${addr}`);
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
