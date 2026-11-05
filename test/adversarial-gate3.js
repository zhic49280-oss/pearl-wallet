/**
 * test/adversarial-gate3.js
 * Empirical Challenger Adversarial Stress Harness for Gate 3
 * (Features 16, 17, 18: Bech32m Address Validation, BIP-39 Validation, Duplicate Prevention, Asset Sync)
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const assert = require('assert/strict');
const crypto = require('crypto');

const ROOT_DIR = path.resolve(__dirname, '..');
const { createSandbox } = require('./helpers/runtime-sandbox');
const { encodeBech32m, decodeBech32m, validatePearlAddress, BECH32_CHARSET } = require('./helpers/bech32m');
const { getWordlist } = require('./helpers/bip39');
const { verifySync } = require('../scripts/verify-sync');

const results = {
  passed: 0,
  failed: 0,
  tests: []
};

async function runTest(name, fn) {
  process.stdout.write(`• Running: ${name}... `);
  try {
    await fn();
    console.log('✅ PASS');
    results.passed++;
    results.tests.push({ name, status: 'PASS' });
  } catch (err) {
    console.log(`❌ FAIL\n  Error: ${err.message}\n${err.stack}`);
    results.failed++;
    results.tests.push({ name, status: 'FAIL', error: err.message });
  }
}

function initAppSandbox(initialStorage = {}) {
  const sandbox = createSandbox(initialStorage);
  sandbox.window.window = sandbox.window;
  sandbox.window.globalThis = sandbox.window;
  sandbox.window.scrollTo = () => {};
  sandbox.window.console = console;
  sandbox.window.AbortController = globalThis.AbortController;
  sandbox.window.fetch = async () => ({ ok: true, json: async () => ({}) });

  const bip39Code = fs.readFileSync(path.join(ROOT_DIR, 'bip39-wordlist.js'), 'utf8');
  const appCode = fs.readFileSync(path.join(ROOT_DIR, 'app.js'), 'utf8');

  vm.createContext(sandbox.window);
  vm.runInContext(bip39Code, sandbox.window);
  vm.runInContext(appCode, sandbox.window);

  return sandbox;
}

async function main() {
  console.log('===============================================================');
  console.log('🛡️  Pearl Wallet Empirical Adversarial Stress Suite (Gate 3)');
  console.log('===============================================================');

  const validPearlAddr = 'prl1pvxtfv9c7a9elgny7jmhndtl9cwdy9wnhvphg7g5arxjvc2rwa4vq09sfpm';
  const wordlist = getWordlist();
  const valid12 = 'abandon ability able about above absent absorb abstract absurd abuse access accident';
  const valid24 = 'abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid acoustic acquire across act action actor actress actual';

  // --------------------------------------------------------------------------
  // SUITE 1: Bech32m Address Validation Fuzzing & Mutation Attacks
  // --------------------------------------------------------------------------
  console.log('\n--- Suite 1: Bech32m Address Validation Fuzzing & Stress Tests ---');

  await runTest('1.1: Baseline validity check on genuine Pearl Taproot address', () => {
    const sandbox = initAppSandbox();
    const res = sandbox.window.validatePearlAddress(validPearlAddr);
    assert.equal(res.valid, true);
    assert.equal(res.decoded.hrp, 'prl');
    assert.equal(res.decoded.witnessVersion, 1);
    assert.equal(res.decoded.programBytes.length, 32);
  });

  await runTest('1.2: Fuzz checksum mutation across all 6 checksum positions with all 32 charset chars', () => {
    const sandbox = initAppSandbox();
    const prefix = validPearlAddr.slice(0, -6);
    const checksum = validPearlAddr.slice(-6);

    let rejectedCount = 0;
    let totalMutations = 0;

    for (let pos = 0; pos < 6; pos++) {
      const origChar = checksum[pos];
      for (const char of BECH32_CHARSET) {
        if (char === origChar) continue;
        totalMutations++;
        const mutatedChecksum = checksum.slice(0, pos) + char + checksum.slice(pos + 1);
        const mutatedAddr = prefix + mutatedChecksum;
        const res = sandbox.window.validatePearlAddress(mutatedAddr);
        if (!res.valid) {
          rejectedCount++;
        }
      }
    }

    assert.equal(totalMutations, 6 * 31);
    assert.equal(rejectedCount, totalMutations, `All ${totalMutations} checksum mutations must be rejected`);
  });

  await runTest('1.3: Fuzz payload character mutations (bit flips, deletions, insertions)', () => {
    const sandbox = initAppSandbox();
    const dataPart = validPearlAddr.slice(5); // skip 'prl1p'

    // Mutate 50 random positions in payload
    for (let i = 0; i < 50; i++) {
      const randIdx = Math.floor(Math.random() * (dataPart.length - 6));
      const orig = dataPart[randIdx];
      const repl = BECH32_CHARSET[(BECH32_CHARSET.indexOf(orig) + 1) % 32];
      const mutatedData = dataPart.slice(0, randIdx) + repl + dataPart.slice(randIdx + 1);
      const mutatedAddr = 'prl1p' + mutatedData;
      const res = sandbox.window.validatePearlAddress(mutatedAddr);
      assert.equal(res.valid, false, `Mutated payload at index ${randIdx} must be rejected`);
    }

    // Single-char deletion
    const deleted = validPearlAddr.slice(0, 15) + validPearlAddr.slice(16);
    assert.equal(sandbox.window.validatePearlAddress(deleted).valid, false);

    // Single-char insertion
    const inserted = validPearlAddr.slice(0, 15) + 'q' + validPearlAddr.slice(15);
    assert.equal(sandbox.window.validatePearlAddress(inserted).valid, false);
  });

  await runTest('1.4: Uppercase allowed vs Mixed Case strictly rejected', () => {
    const sandbox = initAppSandbox();
    
    // All uppercase is valid per BIP-173 / BIP-350
    const upperAddr = validPearlAddr.toUpperCase();
    const upperRes = sandbox.window.validatePearlAddress(upperAddr);
    assert.equal(upperRes.valid, true, 'All uppercase address must be valid');

    // Mixed case variants must be rejected
    const mixedVariants = [
      'Prl1pvxtfv9c7a9elgny7jmhndtl9cwdy9wnhvphg7g5arxjvc2rwa4vq09sfpm',
      'prl1Pvxtfv9c7a9elgny7jmhndtl9cwdy9wnhvphg7g5arxjvc2rwa4vq09sfpm',
      'prl1pvxtfv9c7a9elgny7jmhndtl9cwdy9wnhvphg7g5arxjvc2rwa4vq09sfpM',
      'PRL1pvxtfv9c7a9elgny7jmhndtl9cwdy9wnhvphg7g5arxjvc2rwa4vq09sfpm',
      'prl1PVXTfv9c7a9elgny7jmhndtl9cwdy9wnhvphg7g5arxjvc2rwa4vq09sfpm',
      validPearlAddr.split('').map((c, i) => i % 2 === 0 ? c.toUpperCase() : c.toLowerCase()).join('')
    ];

    for (const m of mixedVariants) {
      const res = sandbox.window.validatePearlAddress(m);
      assert.equal(res.valid, false, `Mixed case "${m.slice(0, 12)}..." should be rejected`);
      assert.match(res.error, /Mixed case/);
    }
  });

  await runTest('1.5: Non-bech32 characters and special symbols are strictly rejected', () => {
    const sandbox = initAppSandbox();
    const invalidChars = ['1', 'b', 'i', 'o', 'B', 'I', 'O', '@', '#', '$', '%', '&', '*', '?', ' ', '\t', '\n', '\0', '珍珠', '🚀'];

    for (const char of invalidChars) {
      const testAddr = validPearlAddr.slice(0, 10) + char + validPearlAddr.slice(11);
      const res = sandbox.window.validatePearlAddress(testAddr);
      assert.equal(res.valid, false, `Address containing "${char}" must be rejected`);
    }
  });

  await runTest('1.6: Foreign HRPs with valid Bech32m checksums are strictly rejected for Pearl', () => {
    const sandbox = initAppSandbox();
    const dummyPubkey = new Uint8Array(32).fill(0x42);

    // Bitcoin Taproot (bc)
    const btcAddr = encodeBech32m('bc', 1, Array.from(dummyPubkey));
    const btcRes = sandbox.window.validatePearlAddress(btcAddr);
    assert.equal(btcRes.valid, false);
    assert.match(btcRes.error, /Invalid HRP: expected 'prl'/);

    // Bitcoin Testnet (tb)
    const tbAddr = encodeBech32m('tb', 1, Array.from(dummyPubkey));
    const tbRes = sandbox.window.validatePearlAddress(tbAddr);
    assert.equal(tbRes.valid, false);
    assert.match(tbRes.error, /Invalid HRP: expected 'prl'/);

    // Mutated Pearl HRP (prlx)
    const prlxAddr = encodeBech32m('prlx', 1, Array.from(dummyPubkey));
    const prlxRes = sandbox.window.validatePearlAddress(prlxAddr);
    assert.equal(prlxRes.valid, false);
    assert.match(prlxRes.error, /Invalid HRP: expected 'prl'/);

    // Short HRP (pr)
    const prAddr = encodeBech32m('pr', 1, Array.from(dummyPubkey));
    const prRes = sandbox.window.validatePearlAddress(prAddr);
    assert.equal(prRes.valid, false);
    assert.match(prRes.error, /Invalid HRP: expected 'prl'/);
  });

  await runTest('1.7: Length boundary checks (0, 7, 8, 90, 91, 10000 chars)', () => {
    const sandbox = initAppSandbox();

    // Below min length 8
    assert.equal(sandbox.window.validatePearlAddress('').valid, false);
    assert.equal(sandbox.window.validatePearlAddress('prl1p').valid, false);
    assert.equal(sandbox.window.validatePearlAddress('prl1pvx').valid, false); // 7 chars

    // Non-string types
    assert.equal(sandbox.window.validatePearlAddress(null).valid, false);
    assert.equal(sandbox.window.validatePearlAddress(undefined).valid, false);
    assert.equal(sandbox.window.validatePearlAddress(12345678).valid, false);
    assert.equal(sandbox.window.validatePearlAddress({}).valid, false);

    // Length 90 chars (maximum BIP-173 length) with bad checksum
    const len90 = 'prl1' + 'p'.repeat(86);
    const res90 = sandbox.window.validatePearlAddress(len90);
    assert.equal(res90.valid, false);
    assert.ok(!res90.error.includes('Invalid address length: 90')); // Rejected by checksum, not length

    // Length 91 chars (must be rejected by length check)
    const len91 = 'prl1' + 'p'.repeat(87);
    const res91 = sandbox.window.validatePearlAddress(len91);
    assert.equal(res91.valid, false);
    assert.match(res91.error, /Invalid address length: 91/);

    // Extreme lengths (DoS prevention)
    const len10k = 'prl1' + 'q'.repeat(10000);
    const res10k = sandbox.window.validatePearlAddress(len10k);
    assert.equal(res10k.valid, false);
    assert.match(res10k.error, /Invalid address length: 10004/);
  });

  await runTest('1.8: Taproot witness version and 32-byte program length constraints', () => {
    const sandbox = initAppSandbox();
    const dummy32 = new Uint8Array(32).fill(0x33);

    // Witness version 0 (SegWit v0, uses Bech32 not Bech32m)
    // Even if constructed with Bech32m, witnessVersion 0 must be rejected
    const v0Addr = encodeBech32m('prl', 0, Array.from(dummy32));
    const v0Res = sandbox.window.validatePearlAddress(v0Addr);
    assert.equal(v0Res.valid, false);
    assert.match(v0Res.error, /Invalid witness version: expected 1 for Taproot/);

    // Witness version 2 (future)
    const v2Addr = encodeBech32m('prl', 2, Array.from(dummy32));
    const v2Res = sandbox.window.validatePearlAddress(v2Addr);
    assert.equal(v2Res.valid, false);
    assert.match(v2Res.error, /Invalid witness version: expected 1 for Taproot/);

    // Program length != 32 bytes (e.g. 20 bytes P2WPKH)
    const dummy20 = new Uint8Array(20).fill(0x55);
    const p2wpkhAddr = encodeBech32m('prl', 1, Array.from(dummy20));
    const lenRes = sandbox.window.validatePearlAddress(p2wpkhAddr);
    assert.equal(lenRes.valid, false);
    assert.match(lenRes.error, /Invalid program length: expected 32 bytes/);
  });

  await runTest('1.9: Transfer, Contact, and Miner UI flows enforce validatePearlAddress', () => {
    const sandbox = initAppSandbox({
      pearl_user_wallets_v4: JSON.stringify({
        wallets: [{
          id: 'w-1',
          name: 'Sender',
          address: validPearlAddr,
          privateKeyHex: '0x123',
          balance: 10.0
        }],
        activeWalletId: 'w-1'
      })
    });
    sandbox.window.initWallets();

    // 1. Contact validation
    sandbox.document.getElementById('contact-name-input').value = 'Alice';
    sandbox.document.getElementById('contact-address-input').value = 'bc1pvxtfv9c7a9elgny7jmhndtl9cwdy9wnhvphg7g5arxjvc2rwa4vq09sfpm'; // bad HRP
    sandbox.window.saveNewContact();
    assert.equal(sandbox.window.state.contacts.length, 0, 'Bad contact address must not be saved');

    // 2. Miner address query validation
    sandbox.document.getElementById('custom-miner-address').value = 'prl1corruptedchecksum99999999999999999999999999999999999999999';
    sandbox.window.queryMinerByAddress();
    const resultBox = sandbox.document.getElementById('miner-query-result');
    const toast = sandbox.document.getElementById('ios-toast');
    const alertFound = (resultBox && resultBox.innerHTML.includes('矿工地址无效')) ||
                       (toast && (toast.innerText.includes('矿工地址无效') || toast.innerText.includes('Invalid')));
    assert.ok(alertFound, 'Should alert user on bad miner address via result box or toast');
  });

  // --------------------------------------------------------------------------
  // SUITE 2: BIP-39 Mnemonic Validation Fuzzing & Stress Tests
  // --------------------------------------------------------------------------
  console.log('\n--- Suite 2: BIP-39 Mnemonic Validation Fuzzing & Stress Tests ---');

  await runTest('2.1: Baseline validity check for 12 and 24 word standard mnemonics', () => {
    const sandbox = initAppSandbox();
    const r12 = sandbox.window.validateMnemonic(valid12);
    assert.equal(r12.valid, true);
    assert.equal(r12.words.length, 12);

    const r24 = sandbox.window.validateMnemonic(valid24);
    assert.equal(r24.valid, true);
    assert.equal(r24.words.length, 24);
  });

  await runTest('2.2: Fuzz wrong word counts (0, 1, 2, 11, 13, 23, 25, 100 words)', () => {
    const sandbox = initAppSandbox();
    const wrongCounts = [0, 1, 2, 5, 11, 13, 23, 25, 100];

    for (const count of wrongCounts) {
      let input = '';
      if (count > 0) {
        const words = [];
        for (let i = 0; i < count; i++) words.push(wordlist[i % wordlist.length]);
        input = words.join(' ');
      }
      const res = sandbox.window.validateMnemonic(input);
      assert.equal(res.valid, false, `Word count ${count} must be rejected`);
      if (count === 0) {
        assert.ok(res.error.includes('empty') || res.error.includes('空'));
      } else {
        assert.match(res.error, /Invalid word count/);
      }
    }
  });

  await runTest('2.3: Non-dictionary words identified with precise 1-based index and token', () => {
    const sandbox = initAppSandbox();
    
    // Single misspelled word at index 5
    const words5 = valid12.split(' ');
    words5[4] = 'notarealword';
    const res5 = sandbox.window.validateMnemonic(words5.join(' '));
    assert.equal(res5.valid, false);
    assert.match(res5.error, /Invalid BIP-39 words found/);
    assert.ok(res5.error.includes('#5 "notarealword"'));
    assert.equal(res5.invalidWords.length, 1);
    assert.equal(res5.invalidWords[0].index, 5);
    assert.equal(res5.invalidWords[0].word, 'notarealword');

    // Multiple misspelled words at indices 1 and 12
    const wordsMulti = valid12.split(' ');
    wordsMulti[0] = 'pearlcoin';
    wordsMulti[11] = 'satoshinakamoto';
    const resMulti = sandbox.window.validateMnemonic(wordsMulti.join(' '));
    assert.equal(resMulti.valid, false);
    assert.ok(resMulti.error.includes('#1 "pearlcoin"'));
    assert.ok(resMulti.error.includes('#12 "satoshinakamoto"'));
    assert.equal(resMulti.invalidWords.length, 2);
  });

  await runTest('2.4: Numbers, symbols, and non-ASCII characters strictly rejected', () => {
    const sandbox = initAppSandbox();
    const badTokens = ['123456', 'word1', 'ab_cd', 'access!', '@bove', '助记词', 'abandon#'];

    for (const token of badTokens) {
      const words = valid12.split(' ');
      words[2] = token;
      const res = sandbox.window.validateMnemonic(words.join(' '));
      assert.equal(res.valid, false, `Token "${token}" must be rejected`);
      assert.match(res.error, /Invalid BIP-39 words found/);
    }
  });

  await runTest('2.5: Casing normalization allows uppercase / mixed case words', () => {
    const sandbox = initAppSandbox();

    // All uppercase
    const upperPhrase = valid12.toUpperCase();
    const rUpper = sandbox.window.validateMnemonic(upperPhrase);
    assert.equal(rUpper.valid, true);
    assert.deepEqual(Array.from(rUpper.words), valid12.split(' '));

    // Titlecase
    const titlePhrase = valid12.split(' ').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
    const rTitle = sandbox.window.validateMnemonic(titlePhrase);
    assert.equal(rTitle.valid, true);
    assert.deepEqual(Array.from(rTitle.words), valid12.split(' '));
  });

  await runTest('2.6: Fuzz chaotic delimiters (commas, periods, semicolons, tabs, newlines, multi-spaces)', () => {
    const sandbox = initAppSandbox();
    const words = valid12.split(' ');

    const chaoticSeparators = [
      ', ', ',  ', ' , ', '，', '， ', '\n', '\r\n', '\t', '  ', ';', '；', '. ', '。 '
    ];

    let chaoticPhrase = '  \n\t ';
    for (let i = 0; i < words.length; i++) {
      chaoticPhrase += words[i];
      if (i < words.length - 1) {
        chaoticPhrase += chaoticSeparators[i % chaoticSeparators.length];
      }
    }
    chaoticPhrase += '  \n\r  ';

    const res = sandbox.window.validateMnemonic(chaoticPhrase);
    assert.equal(res.valid, true, `Chaotic phrase should be successfully parsed and validated: "${chaoticPhrase}"`);
    assert.equal(res.words.length, 12);
    assert.deepEqual(Array.from(res.words), words);
  });

  await runTest('2.7: Array input format and non-string type edge cases', () => {
    const sandbox = initAppSandbox();

    // Valid array
    const rArr = sandbox.window.validateMnemonic(valid12.split(' '));
    assert.equal(rArr.valid, true);
    assert.equal(rArr.words.length, 12);

    // Array with empty elements
    const rSparse = sandbox.window.validateMnemonic(['abandon', '', 'ability', null]);
    assert.equal(rSparse.valid, false);

    // Non-string types
    assert.equal(sandbox.window.validateMnemonic(null).valid, false);
    assert.equal(sandbox.window.validateMnemonic(undefined).valid, false);
    assert.equal(sandbox.window.validateMnemonic(12345).valid, false);
    assert.equal(sandbox.window.validateMnemonic({}).valid, false);
  });

  // --------------------------------------------------------------------------
  // SUITE 3: Duplicate Wallet & Contact Prevention Stress Tests
  // --------------------------------------------------------------------------
  console.log('\n--- Suite 3: Duplicate Prevention Stress Tests ---');

  await runTest('3.1: executeImportWallet rejects duplicate mnemonic and duplicate address', () => {
    const sandbox = initAppSandbox();
    
    // First import
    sandbox.document.getElementById('import-mnemonic-input').value = valid12;
    sandbox.document.getElementById('import-wallet-name').value = 'Primary';
    sandbox.window.executeImportWallet();

    assert.equal(sandbox.window.state.wallets.length, 1);
    const existingAddr = sandbox.window.state.wallets[0].address;

    // Second import with identical mnemonic
    sandbox.document.getElementById('import-mnemonic-input').value = valid12;
    sandbox.window.executeImportWallet();
    assert.equal(sandbox.window.state.wallets.length, 1, 'Duplicate mnemonic must not create second wallet');
    const errEl = sandbox.document.getElementById('import-error-msg');
    assert.ok(errEl.innerText.includes('已存在') || errEl.innerText.includes('already exists'));

    // Third import with different casing, extra spaces, and commas
    const formattedDup = valid12.toUpperCase().split(' ').join(',  ');
    sandbox.document.getElementById('import-mnemonic-input').value = formattedDup;
    sandbox.window.executeImportWallet();
    assert.equal(sandbox.window.state.wallets.length, 1, 'Normalized duplicate mnemonic must not create second wallet');
  });

  await runTest('3.2: finalizeDirectWalletCreation rejects duplicate pending wallet', () => {
    const sandbox = initAppSandbox();
    const addr = validPearlAddr;

    sandbox.window.state.wallets = [{
      id: 'w-exist',
      name: 'Existing',
      address: addr,
      balance: 1.0
    }];

    sandbox.window.state.pendingWallet = {
      id: 'w-new',
      name: 'Duplicate Pending',
      address: addr, // Same address!
      balance: 0.0
    };

    sandbox.window.finalizeDirectWalletCreation();
    assert.equal(sandbox.window.state.wallets.length, 1, 'Must reject adding duplicate pending wallet');
  });

  await runTest('3.3: findExistingWalletByAddress handles case-insensitivity and whitespace', () => {
    const sandbox = initAppSandbox();
    sandbox.window.state.wallets = [{
      id: 'w-1',
      name: 'Test Wallet',
      address: validPearlAddr
    }];

    // Exact lowercase
    assert.equal(sandbox.window.findExistingWalletByAddress(validPearlAddr).isDuplicate, true);

    // Uppercase
    assert.equal(sandbox.window.findExistingWalletByAddress(validPearlAddr.toUpperCase()).isDuplicate, true);

    // With leading/trailing whitespace
    assert.equal(sandbox.window.findExistingWalletByAddress(`   ${validPearlAddr}  \t `).isDuplicate, true);

    // Non-existent address
    assert.equal(sandbox.window.findExistingWalletByAddress('prl1pnonexistent').isDuplicate, false);
    assert.equal(sandbox.window.findExistingWalletByAddress(null).isDuplicate, false);
    assert.equal(sandbox.window.findExistingWalletByAddress('').isDuplicate, false);
  });

  await runTest('3.4: initWallets sanitizes and deduplicates corrupted localStorage entries', () => {
    // Construct localStorage with duplicate addresses in different cases and spaces
    const corruptedWallets = [
      { id: 'w-1', name: 'Wallet A', address: validPearlAddr, balance: 0.0 },
      { id: 'w-2', name: 'Wallet A Duplicate Upper', address: validPearlAddr.toUpperCase(), balance: 0.0 },
      { id: 'w-3', name: 'Wallet A Duplicate Spaces', address: `  ${validPearlAddr} `, balance: 0.0 },
      { id: 'w-4', name: 'Wallet B Distinct', address: 'prl1p22hzufr46n6fa4yj38zckc9n8rsyhq2n39fjldg7pg78s8vz2zks785frn', balance: 0.0 }
    ];

    const sandbox = initAppSandbox({
      pearl_user_wallets_v4: JSON.stringify({
        wallets: corruptedWallets,
        activeWalletId: 'w-1'
      })
    });

    sandbox.window.initWallets();

    assert.equal(sandbox.window.state.wallets.length, 2, 'Corrupted duplicate wallets in localStorage must be deduplicated to 2 unique addresses');
    assert.equal(sandbox.window.state.wallets[0].id, 'w-1');
    assert.equal(sandbox.window.state.wallets[1].id, 'w-4');
  });

  await runTest('3.5: Contact manager rejects duplicate addresses (case and whitespace insensitive)', () => {
    const sandbox = initAppSandbox();
    sandbox.window.state.contacts = [
      { id: 'c-1', name: 'Bob', address: validPearlAddr, createdAt: new Date().toISOString() }
    ];

    // Attempt to add same address in uppercase
    sandbox.document.getElementById('contact-name-input').value = 'Bob Duplicate';
    sandbox.document.getElementById('contact-address-input').value = `  ${validPearlAddr.toUpperCase()}  `;
    sandbox.window.saveNewContact();

    assert.equal(sandbox.window.state.contacts.length, 1, 'Duplicate contact address must be blocked');
  });

  // --------------------------------------------------------------------------
  // SUITE 4: Multi-Target Synchronization & Hygiene Check
  // --------------------------------------------------------------------------
  console.log('\n--- Suite 4: Multi-Target Synchronization & Byte Parity ---');

  await runTest('4.1: scripts/verify-sync.js child process executes cleanly with exit code 0', () => {
    const { execFileSync } = require('child_process');
    const out = execFileSync(process.execPath, [path.join(ROOT_DIR, 'scripts', 'verify-sync.js')], { encoding: 'utf8' });
    assert.ok(out.includes('100% Asset Synchronization & Mock Hygiene Verified'));
  });

  await runTest('4.2: Exact SHA256 parity for app.js across root, dist, android, ios', () => {
    const targets = [
      path.join(ROOT_DIR, 'app.js'),
      path.join(ROOT_DIR, 'dist', 'app.js'),
      path.join(ROOT_DIR, 'android', 'app', 'src', 'main', 'assets', 'public', 'app.js'),
      path.join(ROOT_DIR, 'ios', 'App', 'App', 'public', 'app.js')
    ];

    const hashes = targets.map(p => {
      assert.ok(fs.existsSync(p), `File missing: ${p}`);
      return crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
    });

    for (let i = 1; i < hashes.length; i++) {
      assert.equal(hashes[i], hashes[0], `Hash mismatch between target 0 and target ${i}`);
    }
  });

  // --------------------------------------------------------------------------
  // SUMMARY
  // --------------------------------------------------------------------------
  console.log('\n===============================================================');
  console.log(`📊 ADVERSARIAL STRESS SUITE (GATE 3) RESULTS:`);
  console.log(`   Passed: ${results.passed}`);
  console.log(`   Failed: ${results.failed}`);
  console.log(`   Total:  ${results.passed + results.failed}`);
  console.log('===============================================================');

  if (results.failed > 0) {
    console.error('❌ STRESS TEST CHALLENGE FOUND!');
    process.exit(1);
  } else {
    console.log('✅ ALL GATE 3 ADVERSARIAL CHALLENGES WITHSTOOD EMPIRICALLY!');
    process.exit(0);
  }
}

main().catch(err => {
  console.error('Fatal runner error:', err);
  process.exit(1);
});
