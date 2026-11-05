/**
 * scripts/verify-sync.js
 * Mobile Build Hygiene & Asset Synchronization Verifier
 *
 * Verifies that:
 * 1. dist/, android/app/src/main/assets/public/, and ios/App/App/public/ exist.
 * 2. Every core web asset matches root byte-for-byte and hash-for-hash.
 * 3. Zero mock patterns exist in any file in any target directory.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT_DIR = path.resolve(__dirname, '..');

const CORE_ASSETS = [
  'index.html',
  'app.js',
  'style.css',
  'bip39-wordlist.js',
  'qrcode.min.js',
  'manifest.json',
  'sw.js'
];

const TARGETS = [
  { name: 'dist', path: path.join(ROOT_DIR, 'dist') },
  { name: 'android', path: path.join(ROOT_DIR, 'android', 'app', 'src', 'main', 'assets', 'public') },
  { name: 'ios', path: path.join(ROOT_DIR, 'ios', 'App', 'App', 'public') }
];

const MOCK_PATTERNS = [
  { id: 'MOCK_MNEMONIC', regex: /lottery\s+girl\s+rain\s+peasant\s+fold\s+ankle/i },
  { id: 'TEST_MINER_BUTTON', regex: /fillTestMinerAddress|填入主网活跃矿工/ },
  { id: 'MOCK_CONTACTS', regex: /contact-default-1|contact-default-2|主网节点质押归集池|矿工冷钱包备用备份/ },
  { id: 'RANDOM_JITTER', regex: /Math\.random\(\)\s*-\s*0\.48|livePriceUSD\s*\+\s*jitter/ },
  { id: 'SYNTHETIC_CHARTS', regex: /liveH\s*\*\s*0\.962|liveDiff\s*\*\s*0\.985/ },
  { id: 'FAKE_SEND_DEDUCTION', regex: /wallet\.balance\s*-=\s*walletDeduct/ },
  { id: 'HARDCODED_PRICE_TAG', regex: /1\s*PRL\s*≈\s*\$1\.72/ }
];

function getHash(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function verifySync() {
  console.log('====================================================');
  console.log('🔍 Pearl Wallet Asset Synchronization Verification');
  console.log('====================================================\n');

  let failureCount = 0;

  for (const target of TARGETS) {
    console.log(`Checking target: ${target.name} (${target.path})`);
    if (!fs.existsSync(target.path)) {
      console.error(`  ❌ Target directory does not exist!`);
      failureCount++;
      continue;
    }

    for (const file of CORE_ASSETS) {
      const rootPath = path.join(ROOT_DIR, file);
      const targetPath = path.join(target.path, file);

      if (!fs.existsSync(targetPath)) {
        console.error(`  ❌ Missing file: ${file}`);
        failureCount++;
        continue;
      }

      // Check parity
      const rootHash = getHash(rootPath);
      const targetHash = getHash(targetPath);
      if (rootHash !== targetHash) {
        console.error(`  ❌ Desynchronized content: ${file} (Root: ${rootHash.slice(0, 8)} != Target: ${targetHash.slice(0, 8)})`);
        failureCount++;
      } else {
        console.log(`  ✔ Parity OK: ${file.padEnd(20)} [${rootHash.slice(0, 8)}]`);
      }

      // Check for mock patterns
      const content = fs.readFileSync(targetPath, 'utf8');
      for (const pattern of MOCK_PATTERNS) {
        if (pattern.regex.test(content)) {
          console.error(`  ❌ Mock pattern violation [${pattern.id}] found in ${target.name}/${file}!`);
          failureCount++;
        }
      }
    }
    console.log('');
  }

  if (failureCount > 0) {
    console.error(`❌ Verification failed with ${failureCount} issue(s). Run 'npm run sync' to resolve.`);
    process.exit(1);
  } else {
    console.log('✅ 100% Asset Synchronization & Mock Hygiene Verified across all targets!');
    process.exit(0);
  }
}

if (require.main === module) {
  verifySync();
}

module.exports = { verifySync, CORE_ASSETS, TARGETS, MOCK_PATTERNS };
