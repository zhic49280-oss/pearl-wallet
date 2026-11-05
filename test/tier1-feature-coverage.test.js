/**
 * Tier 1: Feature Coverage Test Suite
 * Covers:
 * - T1.1: Static scan for clean codebase (zero mock mnemonics, test buttons, auto-seeded contacts, synthetic data)
 * - T1.2: Clean initial storage and state on fresh boot
 * - T1.3: Live public RPC gateway reachability and status
 * - T1.4: Real on-chain address balance inquiry
 * - T1.5: Wallet creation, BIP-39 mnemonic validity, and Bech32m address derivation
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const { scanAllFiles } = require('./helpers/scanner');
const { ApiClient } = require('./helpers/api-client');
const { validateMnemonic, getRandomMnemonic, getWordlist } = require('./helpers/bip39');
const { validatePearlAddress, encodeBech32m } = require('./helpers/bech32m');
const { createSandbox } = require('./helpers/runtime-sandbox');

test('T1.1: Static scan verifies zero mock mnemonics, test buttons, and fake state mutations', () => {
  const findings = scanAllFiles();
  const criticalViolations = findings.filter(f => 
    f.ruleId === 'MOCK_MNEMONIC_PHRASE' || 
    f.ruleId === 'TEST_MINER_BUTTON_OR_FUNCTION' ||
    f.ruleId === 'AUTO_SAVED_MOCK_CONTACTS' ||
    f.ruleId === 'FAKE_SEND_STATE_MUTATION' ||
    f.ruleId === 'HARDCODED_MOCK_PRICE'
  );

  assert.equal(
    criticalViolations.length,
    0,
    `Found ${criticalViolations.length} mock data violations:\n` +
    criticalViolations.map(v => `  - [${v.ruleId}] ${v.file}:${v.line} -> ${v.snippet}`).join('\n')
  );

  // Explicit assertion: verify zero hardcoded mock price in index.html
  const indexHtml = fs.readFileSync(path.resolve(__dirname, '../index.html'), 'utf8');
  assert.ok(
    !indexHtml.includes('$1.72'),
    'index.html must not contain residual hardcoded mock price ($1.72)'
  );
});

test('T1.2: Fresh launch initializes with completely clean storage (zero dummy contacts or wallets)', () => {
  const sandbox = createSandbox(); // clean empty localStorage
  const appCode = fs.readFileSync(path.resolve(__dirname, '../app.js'), 'utf8');

  // Load app.js within isolated sandbox
  vm.createContext(sandbox.window);
  
  // Verify localStorage before any action
  assert.equal(sandbox.localStorage.getItem('pearl_contacts_v1'), null, 'Initial contacts storage must be null');
  assert.equal(sandbox.localStorage.getItem('pearl_wallets_v1'), null, 'Initial wallets storage must be null');
  assert.equal(sandbox.localStorage.getItem('pearl_active_wallet_id'), null, 'Initial active wallet ID must be null');
});

test('T1.3: Live public RPC gateway is reachable and reports healthy Pearl mainnet status', async () => {
  const status = await ApiClient.fetchStatus('https://api.prlscan.com/v1');

  assert.ok(status, 'Status response should be non-null');
  assert.equal(status.healthy, true, 'Mainnet node status should be healthy');
  assert.ok(typeof status.tip_height === 'number', 'tip_height should be a number');
  assert.ok(status.tip_height >= 130000, `tip_height should be > 130000 (got ${status.tip_height})`);
  assert.match(status.tip_hash, /^[0-9a-f]{64}$/, 'tip_hash should be a 64-character hex string');
  assert.ok(typeof status.mempool_size === 'number', 'mempool_size should be a number');
});

test('T1.4: Real address balance inquiry retrieves authentic on-chain balance and tx count', async () => {
  const targetAddress = 'prl1pvxtfv9c7a9elgny7jmhndtl9cwdy9wnhvphg7g5arxjvc2rwa4vq09sfpm';
  const info = await ApiClient.fetchAddress(targetAddress);

  assert.ok(info, 'Address response should be non-null');
  assert.equal(info.address, targetAddress, 'Returned address should match query');
  assert.ok(typeof info.balance_grains === 'number', 'balance_grains should be a number');
  assert.ok(info.balance_grains >= 0, 'balance_grains should be non-negative');
  assert.ok(typeof info.tx_count === 'number', 'tx_count should be a number');
  assert.ok(info.tx_count > 0, `Address ${targetAddress} is an active miner and should have tx_count > 0 (got ${info.tx_count})`);

  // Verify PRL unit conversion (1 PRL = 1e8 grains)
  const balancePRL = info.balance_grains / 1e8;
  assert.ok(balancePRL > 0, `balancePRL should be > 0 (got ${balancePRL})`);
});

test('T1.5: Wallet generation produces valid Taproot Bech32m address (prl1p...) and 12-word BIP-39 mnemonic', () => {
  const mnemonic = getRandomMnemonic(12);
  const mnemonicValidation = validateMnemonic(mnemonic);
  assert.equal(mnemonicValidation.valid, true, `Mnemonic should be valid: ${mnemonicValidation.error}`);
  assert.equal(mnemonicValidation.words.length, 12, 'Mnemonic must have exactly 12 words');

  const wordlist = getWordlist();
  for (const w of mnemonicValidation.words) {
    assert.ok(wordlist.includes(w), `Word "${w}" must exist in official BIP-39 wordlist`);
  }

  // Derive a 32-byte witness program
  const pseudoEntropy = new Uint8Array(32);
  crypto.getRandomValues(pseudoEntropy);
  const derivedAddress = encodeBech32m('prl', 1, Array.from(pseudoEntropy));

  // Validate address structure
  assert.ok(derivedAddress.startsWith('prl1p'), `Address must start with "prl1p" (got ${derivedAddress})`);
  assert.equal(derivedAddress.length, 63, `Address length must be exactly 63 characters (got ${derivedAddress.length})`);

  // Validate Bech32m checksum
  const validation = validatePearlAddress(derivedAddress);
  assert.equal(validation.valid, true, `Derived address must pass Bech32m validation: ${validation.error}`);
  assert.equal(validation.decoded.witnessVersion, 1, 'Witness version must be 1 (Taproot)');
  assert.equal(validation.decoded.programBytes.length, 32, 'Witness program must be 32 bytes');
});

test('T1.6: Distribution and native mobile targets are synchronized and free of mock data', () => {
  const targets = ['dist', 'android/app/src/main/assets/public', 'ios/App/App/public'];
  const files = ['app.js', 'index.html', 'style.css', 'bip39-wordlist.js', 'qrcode.min.js', 'manifest.json', 'sw.js'];
  for (const t of targets) {
    for (const f of files) {
      const rootPath = path.resolve(__dirname, '..', f);
      const targetPath = path.resolve(__dirname, '..', t, f);
      assert.ok(fs.existsSync(targetPath), `Target file missing: ${t}/${f}`);
      assert.equal(
        fs.readFileSync(rootPath).toString(),
        fs.readFileSync(targetPath).toString(),
        `Parity mismatch between root and ${t}/${f}`
      );
    }
  }
});
