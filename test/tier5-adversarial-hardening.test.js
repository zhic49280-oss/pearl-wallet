/**
 * Tier 5: Adversarial Coverage Hardening & White-Box Edge Cases
 * 
 * Exercises critical white-box vulnerabilities and boundary edge cases:
 * - T5.1: Wallet list modal rendering & localStorage balance hydration (undefined, null, string, NaN)
 * - T5.2: Address trimming defense-in-depth (leading/trailing spaces, newlines, tabs)
 * - T5.3: Global helpers exposure (window.showToast, window.triggerHaptic, inline onclick integrity)
 * - T5.4: Public REST API gateway payload boundaries (string grains, null items, direct array)
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const ROOT_DIR = path.resolve(__dirname, '..');
const { createSandbox } = require('./helpers/runtime-sandbox');
const { validatePearlAddress } = require('./helpers/bech32m');

const VALID_PEARL_ADDR = 'prl1pvxtfv9c7a9elgny7jmhndtl9cwdy9wnhvphg7g5arxjvc2rwa4vq09sfpm';

function initAppSandbox(initialStorage = {}) {
  const sandbox = createSandbox(initialStorage);
  sandbox.window.window = sandbox.window;
  sandbox.window.globalThis = sandbox.window;
  sandbox.window.scrollTo = () => {};
  sandbox.window.AbortController = globalThis.AbortController;
  sandbox.window.fetch = async () => ({
    ok: true,
    status: 200,
    json: async () => ({})
  });

  const bip39Code = fs.readFileSync(path.join(ROOT_DIR, 'bip39-wordlist.js'), 'utf8');
  const appCode = fs.readFileSync(path.join(ROOT_DIR, 'app.js'), 'utf8');

  vm.createContext(sandbox.window);
  vm.runInContext(bip39Code, sandbox.window);
  vm.runInContext(appCode, sandbox.window);

  return sandbox;
}

// ============================================================================
// T5.1: Wallet List Modal Rendering & LocalStorage Hydration Robustness
// ============================================================================

test('T5.1.1: Stored wallet with valid numeric balance renders cleanly', () => {
  const sandbox = initAppSandbox({
    'pearl_user_wallets_v4': JSON.stringify({
      wallets: [{
        id: 'w_valid',
        name: 'Valid Wallet',
        address: VALID_PEARL_ADDR,
        balance: 10.5
      }],
      activeWalletId: 'w_valid'
    })
  });

  assert.doesNotThrow(() => {
    sandbox.window.initWallets();
  }, 'initWallets should not throw with valid numeric balance');

  const container = sandbox.document.getElementById('wallets-list-container');
  assert.ok(container.innerHTML.includes('10.50 PRL'), 'Should render formatted 10.50 PRL');
});

test('T5.1.2: Stored wallet with undefined balance must not throw TypeError (app.js:1671)', () => {
  const sandbox = initAppSandbox({
    'pearl_user_wallets_v4': JSON.stringify({
      wallets: [{
        id: 'w_no_bal',
        name: 'Missing Balance Wallet',
        address: VALID_PEARL_ADDR
        // balance is undefined
      }],
      activeWalletId: 'w_no_bal'
    })
  });

  // Target requirement: initWallets() must survive undefined balance without throwing TypeError
  assert.doesNotThrow(() => {
    sandbox.window.initWallets();
  }, 'initWallets must sanitize undefined balance and not throw TypeError in renderWalletsListModal');

  const container = sandbox.document.getElementById('wallets-list-container');
  assert.ok(
    container.innerHTML.includes('0.00 PRL'),
    'Should safely default undefined balance to 0.00 PRL'
  );
});

test('T5.1.3: Stored wallet with null balance must not throw TypeError in renderWalletsListModal', () => {
  const sandbox = initAppSandbox({
    'pearl_user_wallets_v4': JSON.stringify({
      wallets: [{
        id: 'w_null_bal',
        name: 'Null Balance Wallet',
        address: VALID_PEARL_ADDR,
        balance: null
      }],
      activeWalletId: 'w_null_bal'
    })
  });

  assert.doesNotThrow(() => {
    sandbox.window.initWallets();
  }, 'initWallets must sanitize null balance and not throw TypeError');

  const container = sandbox.document.getElementById('wallets-list-container');
  assert.ok(
    container.innerHTML.includes('0.00 PRL'),
    'Should safely default null balance to 0.00 PRL'
  );
});

test('T5.1.4: Stored wallet with string balance must not throw TypeError', () => {
  const sandbox = initAppSandbox({
    'pearl_user_wallets_v4': JSON.stringify({
      wallets: [{
        id: 'w_str_bal',
        name: 'String Balance Wallet',
        address: VALID_PEARL_ADDR,
        balance: '25.75'
      }],
      activeWalletId: 'w_str_bal'
    })
  });

  assert.doesNotThrow(() => {
    sandbox.window.initWallets();
  }, 'initWallets must handle string balance without throwing TypeError');

  const container = sandbox.document.getElementById('wallets-list-container');
  assert.ok(
    container.innerHTML.includes('25.75 PRL'),
    'Should coerce string balance to number and render 25.75 PRL'
  );
});

// ============================================================================
// T5.2: Address Trimming & Whitespace Defense-in-Depth
// ============================================================================

test('T5.2.1: Baseline canonical Pearl address passes validation', () => {
  const sandbox = initAppSandbox();
  const res = sandbox.window.validatePearlAddress(VALID_PEARL_ADDR);
  assert.equal(res.valid, true, 'Valid canonical address must pass');
});

test('T5.2.2: Address with leading/trailing whitespace defense-in-depth', () => {
  const sandbox = initAppSandbox();

  // Test address with leading space
  const leadingRes = sandbox.window.validatePearlAddress(' ' + VALID_PEARL_ADDR);
  // Defense-in-depth: either auto-trim to valid, or if rejected, error must identify whitespace
  assert.ok(
    leadingRes.valid === true || (leadingRes.error && /space|whitespace|trim/i.test(leadingRes.error)),
    `Leading whitespace should either be trimmed or clearly identified, got: ${leadingRes.error}`
  );

  // Test address with trailing space
  const trailingRes = sandbox.window.validatePearlAddress(VALID_PEARL_ADDR + ' ');
  assert.ok(
    trailingRes.valid === true || (trailingRes.error && /space|whitespace|trim/i.test(trailingRes.error)),
    `Trailing whitespace should either be trimmed or clearly identified, got: ${trailingRes.error}`
  );

  // Test address with tabs/newlines
  const newlineRes = sandbox.window.validatePearlAddress('\n' + VALID_PEARL_ADDR + '\t');
  assert.ok(
    newlineRes.valid === true || (newlineRes.error && /space|whitespace|trim/i.test(newlineRes.error)),
    `Newline/tab whitespace should either be trimmed or clearly identified, got: ${newlineRes.error}`
  );
});

// ============================================================================
// T5.3: Global Helpers Exposure & Inline HTML Event Handler Integrity
// ============================================================================

test('T5.3.1: showToast is exposed on window and globalThis as a callable function', () => {
  const sandbox = initAppSandbox();

  assert.equal(
    typeof sandbox.window.showToast,
    'function',
    'window.showToast must be a function for runtime feedback and native bridge integration'
  );
  assert.equal(
    typeof sandbox.window.globalThis.showToast,
    'function',
    'globalThis.showToast must be a function'
  );
});

test('T5.3.2: triggerHaptic is exposed on window and globalThis as a callable function', () => {
  const sandbox = initAppSandbox();

  assert.equal(
    typeof sandbox.window.triggerHaptic,
    'function',
    'window.triggerHaptic must be a function so inline HTML onclick calls succeed'
  );
  assert.equal(
    typeof sandbox.window.globalThis.triggerHaptic,
    'function',
    'globalThis.triggerHaptic must be a function'
  );
});

test('T5.3.3: Every function called in index.html inline onclick handlers exists on window', () => {
  const sandbox = initAppSandbox();
  const html = fs.readFileSync(path.join(ROOT_DIR, 'index.html'), 'utf8');

  // Extract all onclick handler expressions
  const regex = /onclick\s*=\s*['"]([^'"]+)['"]/g;
  let match;
  const missingFunctions = new Set();
  const checkedFunctions = new Set();

  while ((match = regex.exec(html)) !== null) {
    const expr = match[1];
    // Find all identifiers preceding an opening parenthesis
    const calls = expr.match(/([a-zA-Z0-9_$]+)\s*\(/g) || [];
    for (const c of calls) {
      const fnName = c.replace('(', '').trim();
      checkedFunctions.add(fnName);
      if (typeof sandbox.window[fnName] !== 'function') {
        missingFunctions.add(fnName);
      }
    }
  }

  assert.ok(checkedFunctions.size > 0, 'Must have inspected onclick handlers in index.html');
  assert.equal(
    missingFunctions.size,
    0,
    `The following functions are called in index.html onclick handlers but missing from window:\n` +
    Array.from(missingFunctions).map(f => `  - window.${f} is undefined`).join('\n')
  );
});

// ============================================================================
// T5.4: Public REST API Gateway Payload Boundary & Type Safety
// ============================================================================

test('T5.4.1: fetchAddressBalance parses stringified balance_grains correctly', async () => {
  const sandbox = initAppSandbox();

  // Simulate API returning balance_grains as a string
  sandbox.window.fetch = async (url) => {
    return {
      ok: true,
      status: 200,
      json: async () => ({
        balance_grains: '500000000', // 5 PRL represented as string
        received_grains: '500000000',
        sent_grains: '0',
        tx_count: 1
      })
    };
  };

  const balance = await sandbox.window.fetchAddressBalance(VALID_PEARL_ADDR);
  assert.equal(
    balance,
    5.0,
    `fetchAddressBalance should coerce string grains to number (expected 5.0, got ${balance})`
  );
});

test('T5.4.2: fetchAddressTransactions handles null/sparse elements in items array safely', async () => {
  const sandbox = initAppSandbox();

  // Simulate API returning items array with null or undefined entries
  sandbox.window.fetch = async (url) => {
    return {
      ok: true,
      status: 200,
      json: async () => ({
        items: [
          null,
          undefined,
          { txid: 'valid_tx', delta_grains: 100000000, time: '2026-11-04T00:00:00Z', status: 'confirmed' }
        ]
      })
    };
  };

  let txs;
  await assert.doesNotReject(async () => {
    txs = await sandbox.window.fetchAddressTransactions(VALID_PEARL_ADDR);
  }, 'fetchAddressTransactions should not throw TypeError when encountering null item');

  assert.ok(Array.isArray(txs), 'Should return an array');
  assert.equal(txs.length, 1, 'Should filter out null entries and retain valid tx');
});

test('T5.4.3: fetchAddressTransactions handles direct JSON array response safely', async () => {
  const sandbox = initAppSandbox();

  // Simulate alternate API proxy returning array directly instead of { items: [...] }
  sandbox.window.fetch = async (url) => {
    return {
      ok: true,
      status: 200,
      json: async () => ([
        { txid: 'direct_tx_1', delta_grains: 200000000, time: '2026-11-04T00:00:00Z', status: 'confirmed' }
      ])
    };
  };

  const txs = await sandbox.window.fetchAddressTransactions(VALID_PEARL_ADDR);
  assert.ok(Array.isArray(txs), 'Should return an array');
  assert.equal(
    txs.length,
    1,
    `Should recognize direct array responses (expected 1 item, got ${txs.length})`
  );
});
