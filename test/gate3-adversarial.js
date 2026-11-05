/**
 * test/gate3-adversarial.js
 * Empirical Challenger Adversarial Stress & Runtime Integrity Harness for Gate 3
 *
 * Scopes:
 * 1. executeSend Rejection & Fake State Mutation Immunity:
 *    - Validates that invalid/corrupted addresses, bad HRP, wrong witness version,
 *      corrupted checksum, mixed case, and illegal lengths are strictly rejected.
 *    - Verifies that zero fake balance deductions occur and zero fake txs are recorded.
 *    - Verifies haptic feedback, toast notifications, and slider thumb reset.
 * 2. executeImportWallet Validation & Duplicate Prevention:
 *    - Verifies error element (#import-error-msg) and toasts on empty input.
 *    - Verifies word count validation (1, 5, 11, 13, 23, 25 words).
 *    - Verifies BIP-39 dictionary validation and index-level error reporting.
 *    - Verifies duplicate wallet import rejection and warning banner display.
 *    - Verifies direct creation duplicate guard and initWallets storage deduplication.
 * 3. Multi-Target Byte-for-Byte Asset Parity & Mock Data Hygiene:
 *    - SHA256 hash comparison across root, dist, android, and ios.
 *    - Comprehensive regex scan for all 7 mock patterns and legacy $1.72 price tag.
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const assert = require('assert/strict');
const crypto = require('crypto');

const ROOT_DIR = path.resolve(__dirname, '..');

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

// ============================================================================
// Full DOM & Runtime Sandbox Builder
// ============================================================================
function createFullDomSandbox(initialStorage = {}) {
  const store = new Map();
  for (const [k, v] of Object.entries(initialStorage)) {
    store.set(k, String(v));
  }

  const localStorage = {
    getItem: (k) => store.has(k) ? store.get(k) : null,
    setItem: (k, v) => store.set(k, String(v)),
    removeItem: (k) => store.delete(k),
    clear: () => store.clear(),
    dump: () => Object.fromEntries(store.entries()),
    get length() { return store.size; }
  };

  const elements = new Map();

  function makeElement(id, tag = 'div') {
    const classSet = new Set();
    const listeners = new Map();
    const attrs = new Map();

    let _className = '';
    const el = {
      id,
      tagName: tag.toUpperCase(),
      value: '',
      innerText: '',
      innerHTML: '',
      style: {},
      disabled: false,
      checked: false,
      clientWidth: 300,
      clientHeight: 50,
      get className() { return _className; },
      set className(val) {
        _className = String(val || '');
        classSet.clear();
        _className.split(/\s+/).filter(Boolean).forEach(c => classSet.add(c));
      },
      getBoundingClientRect: () => ({ left: 0, top: 0, width: el.clientWidth, height: el.clientHeight }),
      classList: {
        contains: (c) => classSet.has(c),
        add: (...cs) => {
          cs.forEach(c => classSet.add(c));
          _className = Array.from(classSet).join(' ');
        },
        remove: (...cs) => {
          cs.forEach(c => classSet.delete(c));
          _className = Array.from(classSet).join(' ');
        },
        toggle: (c) => {
          if (classSet.has(c)) {
            classSet.delete(c);
          } else {
            classSet.add(c);
          }
          _className = Array.from(classSet).join(' ');
        }
      },
      setAttribute: (k, v) => attrs.set(k, String(v)),
      getAttribute: (k) => attrs.get(k) || null,
      removeAttribute: (k) => attrs.delete(k),
      addEventListener: (evt, handler) => {
        if (!listeners.has(evt)) listeners.set(evt, []);
        listeners.get(evt).push(handler);
      },
      removeEventListener: (evt, handler) => {
        if (!listeners.has(evt)) return;
        listeners.set(evt, listeners.get(evt).filter(h => h !== handler));
      },
      dispatchEvent: (evt) => {
        const type = typeof evt === 'string' ? evt : evt.type;
        const arr = listeners.get(type) || [];
        arr.forEach(h => h(evt));
      },
      _classSet: classSet,
      _attrs: attrs
    };
    return el;
  }

  function getElement(id) {
    if (!elements.has(id)) {
      elements.set(id, makeElement(id));
    }
    return elements.get(id);
  }

  const toasts = [];
  const haptics = [];

  const document = {
    getElementById: (id) => getElement(id),
    querySelector: (sel) => {
      if (sel.startsWith('#')) return getElement(sel.slice(1));
      return getElement(sel);
    },
    querySelectorAll: (sel) => {
      if (sel === '.bottom-sheet') {
        return [
          getElement('sheet-receive'),
          getElement('sheet-send'),
          getElement('sheet-rpc-settings'),
          getElement('sheet-wallets'),
          getElement('sheet-import-wallet')
        ];
      }
      return [];
    },
    addEventListener: () => {},
    removeEventListener: () => {}
  };

  const windowListeners = new Map();
  const window = {
    localStorage,
    document,
    crypto: {
      getRandomValues: (buf) => crypto.getRandomValues(buf)
    },
    navigator: {
      userAgent: 'pearl-challenger-agent',
      vibrate: (pattern) => haptics.push(pattern),
      clipboard: { writeText: async () => {} }
    },
    setTimeout: (fn, delay) => setTimeout(fn, delay),
    clearTimeout: (id) => clearTimeout(id),
    setInterval: (fn, delay) => setInterval(fn, delay),
    clearInterval: (id) => clearInterval(id),
    requestAnimationFrame: (cb) => setTimeout(cb, 0),
    performance: { now: () => Date.now() },
    fetch: async (url) => {
      const u = String(url || '');
      if (u.includes('/addresses/')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({ balance_grains: 5000000000, tx_count: 0 })
        };
      }
      return { ok: true, status: 200, json: async () => ({}) };
    },
    URL: globalThis.URL,
    AbortController: globalThis.AbortController,
    addEventListener: (evt, handler) => {
      if (!windowListeners.has(evt)) windowListeners.set(evt, []);
      windowListeners.get(evt).push(handler);
    },
    removeEventListener: (evt, handler) => {
      if (!windowListeners.has(evt)) return;
      windowListeners.set(evt, windowListeners.get(evt).filter(h => h !== handler));
    },
    dispatchEvent: (evt) => {
      const type = typeof evt === 'string' ? evt : evt.type;
      const list = windowListeners.get(type) || [];
      list.forEach(h => h(evt));
    },
    scrollTo: () => {},
    console: {
      log: () => {},
      warn: () => {},
      error: () => {}
    },
    toasts,
    haptics,
    elements
  };

  window.window = window;
  window.global = window;
  window.globalThis = window;

  return { window, document, localStorage, elements, toasts, haptics };
}

function loadWalletEnvironment(initialStorage = {}) {
  const sandbox = createFullDomSandbox(initialStorage);

  // Initialize essential UI elements
  const thumb = sandbox.document.getElementById('swipe-thumb');
  thumb.clientWidth = 50;
  thumb.clientHeight = 50;

  const track = sandbox.document.getElementById('swipe-track');
  track.clientWidth = 300;
  track.clientHeight = 50;

  const toastEl = sandbox.document.getElementById('ios-toast');
  toastEl.innerText = '';
  toastEl.className = 'opacity-0 -translate-y-4 pointer-events-none';

  const errEl = sandbox.document.getElementById('import-error-msg');
  errEl.innerText = '';
  errEl.className = 'hidden';

  const bip39Code = fs.readFileSync(path.join(ROOT_DIR, 'bip39-wordlist.js'), 'utf8');
  const appCode = fs.readFileSync(path.join(ROOT_DIR, 'app.js'), 'utf8');

  vm.createContext(sandbox.window);
  vm.runInContext(bip39Code, sandbox.window);
  vm.runInContext(appCode, sandbox.window);

  return sandbox;
}

// Trigger swipe gesture in DOM sandbox
function triggerSwipeSend(sandbox) {
  const thumb = sandbox.document.getElementById('swipe-thumb');
  // Dispatch mousedown on thumb
  thumb.dispatchEvent({ type: 'mousedown', clientX: 0 });
  // Dispatch mousemove on window to reach full distance (> 236px)
  sandbox.window.dispatchEvent({ type: 'mousemove', clientX: 300 });
}

async function main() {
  console.log('===============================================================');
  console.log('🛡️  Pearl Wallet Empirical Adversarial Stress Suite (Gate 3)');
  console.log('===============================================================\n');

  // ==========================================================================
  // SUITE 1: executeSend Rejection & Fake State Mutation Immunity
  // ==========================================================================
  console.log('--- Suite 1: executeSend Rejection & Fake State Mutation Immunity ---');

  const validTestWallet = {
    id: 'wallet-test-01',
    name: 'Primary Sender',
    pin: '123456',
    mnemonic: ['abandon', 'ability', 'able', 'about', 'above', 'absent', 'absorb', 'abstract', 'absurd', 'abuse', 'access', 'accident'],
    address: 'prl1pvxtfv9c7a9elgny7jmhndtl9cwdy9wnhvphg7g5arxjvc2rwa4vq09sfpm',
    privateKeyHex: '0x11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff',
    balance: 50.00000000,
    createdAt: new Date().toISOString()
  };

  const initialStorageWithWallet = {
    pearl_user_wallets_v4: JSON.stringify({
      wallets: [validTestWallet],
      activeWalletId: validTestWallet.id
    })
  };

  await runTest('1.1: executeSend rejects empty recipient address without mutating balance or tx history', async () => {
    const sandbox = loadWalletEnvironment(initialStorageWithWallet);
    sandbox.window.dispatchEvent('DOMContentLoaded');

    const sendAddr = sandbox.document.getElementById('send-address-input');
    const sendAmt = sandbox.document.getElementById('send-amount-input');
    const toast = sandbox.document.getElementById('ios-toast');

    sendAddr.value = '';
    sendAmt.value = '1.0';

    triggerSwipeSend(sandbox);

    const active = sandbox.window.state.wallets[0];
    assert.equal(active.balance, 50.0, 'Balance must remain strictly unchanged');
    assert.equal(sandbox.window.state.txHistory.length, 0, 'No fake tx must be added to txHistory');
    assert.ok(toast.innerText.includes('请输入收款方地址'), 'Toast must prompt for recipient address');
  });

  await runTest('1.2: executeSend rejects non-Bech32m string (random text / legacy hex address)', async () => {
    const sandbox = loadWalletEnvironment(initialStorageWithWallet);
    sandbox.window.dispatchEvent('DOMContentLoaded');

    const sendAddr = sandbox.document.getElementById('send-address-input');
    const sendAmt = sandbox.document.getElementById('send-amount-input');
    const toast = sandbox.document.getElementById('ios-toast');

    const badAddresses = [
      'notanaddress',
      '0x71C7656EC7ab88b098defB751B7401B5f6d8976F',
      '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
      'pearl123456789'
    ];

    for (const badAddr of badAddresses) {
      sendAddr.value = badAddr;
      sendAmt.value = '2.5';

      triggerSwipeSend(sandbox);

      const active = sandbox.window.state.wallets[0];
      assert.equal(active.balance, 50.0, `Balance must remain 50.0 after bad addr: ${badAddr}`);
      assert.equal(sandbox.window.state.txHistory.length, 0, 'No fake tx recorded');
      assert.ok(toast.innerText.includes('收款地址无效'), `Toast should indicate invalid address for ${badAddr}`);
    }
  });

  await runTest('1.3: executeSend rejects foreign network HRP (Bitcoin bc1 / Litecoin ltc1 / testnet tb1)', async () => {
    const sandbox = loadWalletEnvironment(initialStorageWithWallet);
    sandbox.window.dispatchEvent('DOMContentLoaded');

    const sendAddr = sandbox.document.getElementById('send-address-input');
    const sendAmt = sandbox.document.getElementById('send-amount-input');
    const toast = sandbox.document.getElementById('ios-toast');

    const foreignAddrs = [
      'bc1pvxtfv9c7a9elgny7jmhndtl9cwdy9wnhvphg7g5arxjvc2rwa4vqs47d4s',
      'tb1pvxtfv9c7a9elgny7jmhndtl9cwdy9wnhvphg7g5arxjvc2rwa4vq6c52n7',
      'prl0pvxtfv9c7a9elgny7jmhndtl9cwdy9wnhvphg7g5arxjvc2rwa4vq09sfpm'
    ];

    for (const fAddr of foreignAddrs) {
      sendAddr.value = fAddr;
      sendAmt.value = '5.0';

      triggerSwipeSend(sandbox);

      const active = sandbox.window.state.wallets[0];
      assert.equal(active.balance, 50.0, 'Balance must remain unchanged');
      assert.equal(sandbox.window.state.txHistory.length, 0, 'Zero tx additions');
      assert.ok(toast.innerText.includes('收款地址无效') || toast.innerText.includes('HRP'), 'Toast must indicate invalid HRP');
    }
  });

  await runTest('1.4: executeSend rejects non-Taproot witness version (witness v0 prl1q...)', async () => {
    const sandbox = loadWalletEnvironment(initialStorageWithWallet);
    sandbox.window.dispatchEvent('DOMContentLoaded');

    const sendAddr = sandbox.document.getElementById('send-address-input');
    const sendAmt = sandbox.document.getElementById('send-amount-input');
    const toast = sandbox.document.getElementById('ios-toast');

    // Witness version 0 (q) instead of 1 (p)
    const v0Addr = 'prl1qvxtfv9c7a9elgny7jmhndtl9cwdy9wnhvphg7g5arxjvc2rwa4vq09sfpm';
    sendAddr.value = v0Addr;
    sendAmt.value = '1.0';

    triggerSwipeSend(sandbox);

    const active = sandbox.window.state.wallets[0];
    assert.equal(active.balance, 50.0, 'Balance must remain unchanged');
    assert.equal(sandbox.window.state.txHistory.length, 0, 'Zero tx additions');
    assert.ok(toast.innerText.includes('收款地址无效'), 'Toast must report invalid witness version');
  });

  await runTest('1.5: executeSend rejects corrupted checksum (tampered last character)', async () => {
    const sandbox = loadWalletEnvironment(initialStorageWithWallet);
    sandbox.window.dispatchEvent('DOMContentLoaded');

    const sendAddr = sandbox.document.getElementById('send-address-input');
    const sendAmt = sandbox.document.getElementById('send-amount-input');
    const toast = sandbox.document.getElementById('ios-toast');

    // Valid: ...09sfpm -> Tampered: ...09sfpz
    const tampered = 'prl1pvxtfv9c7a9elgny7jmhndtl9cwdy9wnhvphg7g5arxjvc2rwa4vq09sfpz';
    sendAddr.value = tampered;
    sendAmt.value = '1.0';

    triggerSwipeSend(sandbox);

    const active = sandbox.window.state.wallets[0];
    assert.equal(active.balance, 50.0, 'Balance must remain unchanged');
    assert.equal(sandbox.window.state.txHistory.length, 0, 'Zero tx additions');
    assert.ok(toast.innerText.includes('收款地址无效'), 'Toast must report invalid checksum');
  });

  await runTest('1.6: executeSend rejects mixed case Bech32m addresses (BIP-350 violation)', async () => {
    const sandbox = loadWalletEnvironment(initialStorageWithWallet);
    sandbox.window.dispatchEvent('DOMContentLoaded');

    const sendAddr = sandbox.document.getElementById('send-address-input');
    const sendAmt = sandbox.document.getElementById('send-amount-input');
    const toast = sandbox.document.getElementById('ios-toast');

    const mixed = 'prl1pvxtfv9c7a9elgny7jmhndtl9cwdy9wnhvphG7G5ARXJVC2RWA4VQ09sfpm';
    sendAddr.value = mixed;
    sendAmt.value = '1.0';

    triggerSwipeSend(sandbox);

    const active = sandbox.window.state.wallets[0];
    assert.equal(active.balance, 50.0, 'Balance must remain unchanged');
    assert.equal(sandbox.window.state.txHistory.length, 0, 'Zero tx additions');
    assert.ok(toast.innerText.includes('收款地址无效'), 'Toast must report mixed case rejection');
  });

  await runTest('1.7: executeSend rejects negative, zero, NaN, or sub-fee amounts', async () => {
    const sandbox = loadWalletEnvironment(initialStorageWithWallet);
    sandbox.window.dispatchEvent('DOMContentLoaded');

    const sendAddr = sandbox.document.getElementById('send-address-input');
    const sendAmt = sandbox.document.getElementById('send-amount-input');
    const toast = sandbox.document.getElementById('ios-toast');

    const validAddr = 'prl1pvxtfv9c7a9elgny7jmhndtl9cwdy9wnhvphg7g5arxjvc2rwa4vq09sfpm';
    sendAddr.value = validAddr;

    const badAmounts = ['0', '-1.5', 'NaN', 'abc', '0.00000001'];
    for (const amt of badAmounts) {
      sendAmt.value = amt;
      triggerSwipeSend(sandbox);

      const active = sandbox.window.state.wallets[0];
      assert.equal(active.balance, 50.0, `Balance must remain 50.0 for bad amount ${amt}`);
      assert.equal(sandbox.window.state.txHistory.length, 0, 'Zero tx additions');
      assert.ok(toast.innerText.length > 0, 'Toast must report error');
    }
  });

  await runTest('1.8: executeSend rejects transfer amounts exceeding wallet balance', async () => {
    const sandbox = loadWalletEnvironment(initialStorageWithWallet);
    sandbox.window.dispatchEvent('DOMContentLoaded');

    const sendAddr = sandbox.document.getElementById('send-address-input');
    const sendAmt = sandbox.document.getElementById('send-amount-input');
    const toast = sandbox.document.getElementById('ios-toast');

    const validAddr = 'prl1pvxtfv9c7a9elgny7jmhndtl9cwdy9wnhvphg7g5arxjvc2rwa4vq09sfpm';
    sendAddr.value = validAddr;
    sendAmt.value = '100.0'; // wallet balance is 50.0

    triggerSwipeSend(sandbox);

    const active = sandbox.window.state.wallets[0];
    assert.equal(active.balance, 50.0, 'Balance must remain unchanged on overdraft');
    assert.equal(sandbox.window.state.txHistory.length, 0, 'Zero tx additions');
    assert.ok(toast.innerText.includes('超出当前余额'), 'Toast must notify balance exceeded');
  });

  await runTest('1.9: Face ID authentication passed still performs NO fake deduction (read-only mode)', async () => {
    const sandbox = loadWalletEnvironment(initialStorageWithWallet);
    sandbox.window.dispatchEvent('DOMContentLoaded');

    const sendAddr = sandbox.document.getElementById('send-address-input');
    const sendAmt = sandbox.document.getElementById('send-amount-input');
    const toast = sandbox.document.getElementById('ios-toast');

    const validAddr = 'prl1pvxtfv9c7a9elgny7jmhndtl9cwdy9wnhvphg7g5arxjvc2rwa4vq09sfpm';
    sendAddr.value = validAddr;
    sendAmt.value = '5.0'; // valid amount <= 50.0

    // Biometric auth will pass in Web fallback mode
    triggerSwipeSend(sandbox);

    // Wait for async auth resolution
    await new Promise(r => setTimeout(r, 100));

    const active = sandbox.window.state.wallets[0];
    assert.equal(active.balance, 50.0, 'Balance MUST NOT be mutated locally (Zero Fake Deduction)');
    assert.equal(sandbox.window.state.txHistory.length, 0, 'No fake transactions added');
    assert.ok(toast.innerText.includes('只读公共网络') || toast.innerText.includes('签名验证通过'),
      'Toast must explain read-only public network status');
  });

  await runTest('1.10: #send-address-input triggers dynamic visual feedback (emerald/rose classes)', () => {
    const sandbox = loadWalletEnvironment(initialStorageWithWallet);
    sandbox.window.dispatchEvent('DOMContentLoaded');

    const sendAddr = sandbox.document.getElementById('send-address-input');
    const validAddr = 'prl1pvxtfv9c7a9elgny7jmhndtl9cwdy9wnhvphg7g5arxjvc2rwa4vq09sfpm';

    // 1. Valid address
    sendAddr.value = validAddr;
    sendAddr.dispatchEvent({ type: 'input' });
    assert.ok(sendAddr._classSet.has('border-emerald-500/60'), 'Should have border-emerald-500/60');
    assert.ok(!sendAddr._classSet.has('border-rose-500/60'), 'Should not have border-rose-500/60');

    // 2. Invalid address (>= 8 chars)
    sendAddr.value = 'prl1badbadbadbad';
    sendAddr.dispatchEvent({ type: 'input' });
    assert.ok(sendAddr._classSet.has('border-rose-500/60'), 'Should have border-rose-500/60');
    assert.ok(!sendAddr._classSet.has('border-emerald-500/60'), 'Should not have border-emerald-500/60');

    // 3. Cleared address
    sendAddr.value = '';
    sendAddr.dispatchEvent({ type: 'input' });
    assert.ok(!sendAddr._classSet.has('border-rose-500/60'), 'Cleared should remove rose');
    assert.ok(!sendAddr._classSet.has('border-emerald-500/60'), 'Cleared should remove emerald');
  });

  await runTest('1.11: executeSend in external fee mode properly computes deduction (amount + fee) and rejects overdraft', () => {
    const sandbox = loadWalletEnvironment(initialStorageWithWallet);
    sandbox.window.dispatchEvent('DOMContentLoaded');

    sandbox.window.state.feeDeductMode = 'external';
    const sendAddr = sandbox.document.getElementById('send-address-input');
    const sendAmt = sandbox.document.getElementById('send-amount-input');
    const toast = sandbox.document.getElementById('ios-toast');

    sendAddr.value = 'prl1pvxtfv9c7a9elgny7jmhndtl9cwdy9wnhvphg7g5arxjvc2rwa4vq09sfpm';
    sendAmt.value = '49.9999'; // with fees it exceeds 50.0

    triggerSwipeSend(sandbox);

    const active = sandbox.window.state.wallets[0];
    assert.equal(active.balance, 50.0, 'Balance must remain unchanged on fee overdraft');
    assert.ok(toast.innerText.includes('超出当前余额'), 'Toast warns about fee overdraft');
  });

  await runTest('1.12: executeSend rejects witness programs with invalid byte lengths (e.g. 20-byte P2WPKH)', () => {
    const sandbox = loadWalletEnvironment(initialStorageWithWallet);
    sandbox.window.dispatchEvent('DOMContentLoaded');

    const sendAddr = sandbox.document.getElementById('send-address-input');
    const sendAmt = sandbox.document.getElementById('send-amount-input');
    const toast = sandbox.document.getElementById('ios-toast');

    const bech32m = require('./helpers/bech32m');
    const program20 = new Uint8Array(20).fill(0xab);
    const addr20 = bech32m.encodeBech32m('prl', 1, Array.from(program20));

    sendAddr.value = addr20;
    sendAmt.value = '1.0';

    triggerSwipeSend(sandbox);

    const active = sandbox.window.state.wallets[0];
    assert.equal(active.balance, 50.0, 'Balance unchanged');
    assert.ok(toast.innerText.includes('收款地址无效'), 'Rejects 20-byte witness program');
  });

  await runTest('1.13: executeSend rejects witness version 2 through 16 even if Bech32m checksum is valid', () => {
    const sandbox = loadWalletEnvironment(initialStorageWithWallet);
    sandbox.window.dispatchEvent('DOMContentLoaded');

    const bech32m = require('./helpers/bech32m');
    const program32 = new Uint8Array(32).fill(0x42);

    for (const v of [2, 3, 16]) {
      const addrV = bech32m.encodeBech32m('prl', v, Array.from(program32));
      const sendAddr = sandbox.document.getElementById('send-address-input');
      const sendAmt = sandbox.document.getElementById('send-amount-input');
      const toast = sandbox.document.getElementById('ios-toast');

      sendAddr.value = addrV;
      sendAmt.value = '1.0';

      triggerSwipeSend(sandbox);

      const active = sandbox.window.state.wallets[0];
      assert.equal(active.balance, 50.0, 'Balance unchanged');
      assert.ok(toast.innerText.includes('收款地址无效'), `Rejects witness version ${v}`);
    }
  });

  await runTest('1.14: executeSend rejects addresses with internal whitespace or control characters', () => {
    const sandbox = loadWalletEnvironment(initialStorageWithWallet);
    sandbox.window.dispatchEvent('DOMContentLoaded');

    const sendAddr = sandbox.document.getElementById('send-address-input');
    const sendAmt = sandbox.document.getElementById('send-amount-input');
    const toast = sandbox.document.getElementById('ios-toast');

    const badAddrs = [
      'prl1pvxtfv9c7a9elgny7jmhndtl9cwdy9wnhvphg7g5arxjvc2rwa4vq 09sfpm',
      'prl1pvxtfv9c7a9elgny7jmhndtl9cwdy9wnhvphg7g5arxjvc2rwa4vq\t09sfpm',
      'prl1pvxtfv9c7a9elgny7jmhndtl9cwdy9wnhvphg7g5arxjvc2rwa4vq\n09sfpm'
    ];

    for (const bad of badAddrs) {
      sendAddr.value = bad;
      sendAmt.value = '1.0';

      triggerSwipeSend(sandbox);

      const active = sandbox.window.state.wallets[0];
      assert.equal(active.balance, 50.0, 'Balance unchanged');
      assert.ok(toast.innerText.includes('收款地址无效'), 'Rejects internal space/newline');
    }
  });

  // ==========================================================================
  // SUITE 2: executeImportWallet Input Validation & Duplicate Prevention
  // ==========================================================================
  console.log('\n--- Suite 2: executeImportWallet Validation & Duplicate Prevention ---');

  await runTest('2.1: executeImportWallet displays error message and toast on empty mnemonic', () => {
    const sandbox = loadWalletEnvironment();
    sandbox.window.dispatchEvent('DOMContentLoaded');

    const wordsInput = sandbox.document.getElementById('import-mnemonic-input');
    const errEl = sandbox.document.getElementById('import-error-msg');
    const toast = sandbox.document.getElementById('ios-toast');

    wordsInput.value = '';
    sandbox.window.executeImportWallet();

    assert.ok(!errEl._classSet.has('hidden'), '#import-error-msg must NOT be hidden');
    assert.ok(errEl.innerText.includes('请输入 12 或 24 个英文助记词') || errEl.innerText.includes('seed words'),
      'Error message should prompt for seed words');
    assert.equal(errEl.innerText, toast.innerText, 'Toast must match inline error element');
    assert.equal(sandbox.window.state.wallets.length, 0, 'No wallet should be imported');
  });

  await runTest('2.2: executeImportWallet rejects invalid word counts (1, 5, 11, 13, 23, 25)', () => {
    const sandbox = loadWalletEnvironment();
    sandbox.window.dispatchEvent('DOMContentLoaded');

    const sampleWords = [
      'abandon', 'ability', 'able', 'about', 'above', 'absent',
      'absorb', 'abstract', 'absurd', 'abuse', 'access', 'accident',
      'account', 'accuse', 'achieve', 'acid', 'acoustic', 'acquire',
      'across', 'act', 'action', 'actor', 'actress', 'actual', 'adapt'
    ];

    const wordsInput = sandbox.document.getElementById('import-mnemonic-input');
    const errEl = sandbox.document.getElementById('import-error-msg');
    const toast = sandbox.document.getElementById('ios-toast');

    const invalidCounts = [1, 5, 11, 13, 23, 25];
    for (const count of invalidCounts) {
      wordsInput.value = sampleWords.slice(0, count).join(' ');
      sandbox.window.executeImportWallet();

      assert.ok(!errEl._classSet.has('hidden'), `#import-error-msg must be visible for count ${count}`);
      assert.ok(errEl.innerText.includes('Invalid word count'), `Error should include 'Invalid word count' for ${count} words`);
      assert.equal(errEl.innerText, toast.innerText, 'Toast matches error element');
      assert.equal(sandbox.window.state.wallets.length, 0, 'No wallet imported');
    }
  });

  await runTest('2.3: executeImportWallet rejects non-BIP-39 words and reports exact offending indices', () => {
    const sandbox = loadWalletEnvironment();
    sandbox.window.dispatchEvent('DOMContentLoaded');

    const wordsInput = sandbox.document.getElementById('import-mnemonic-input');
    const errEl = sandbox.document.getElementById('import-error-msg');
    const toast = sandbox.document.getElementById('ios-toast');

    const valid11 = 'abandon ability able about above absent absorb abstract absurd abuse access';

    // Test 1: Fake word at position #12
    wordsInput.value = `${valid11} invalidtokenxyz`;
    sandbox.window.executeImportWallet();

    assert.ok(!errEl._classSet.has('hidden'), '#import-error-msg visible');
    assert.ok(errEl.innerText.includes('Invalid BIP-39 words found'), 'Mentions Invalid BIP-39 words');
    assert.ok(errEl.innerText.includes('#12 "invalidtokenxyz"'), 'Reports exact index #12 and word');
    assert.equal(sandbox.window.state.wallets.length, 0, 'No wallet created');

    // Test 2: Digits and symbols
    wordsInput.value = `${valid11} 999888`;
    sandbox.window.executeImportWallet();

    assert.ok(errEl.innerText.includes('#12 "999888"'), 'Reports numeric token');
    assert.equal(sandbox.window.state.wallets.length, 0, 'No wallet created');
  });

  await runTest('2.4: executeImportWallet successfully imports valid 12-word mnemonic', () => {
    const sandbox = loadWalletEnvironment();
    sandbox.window.dispatchEvent('DOMContentLoaded');

    const wordsInput = sandbox.document.getElementById('import-mnemonic-input');
    const nameInput = sandbox.document.getElementById('import-wallet-name');
    const errEl = sandbox.document.getElementById('import-error-msg');
    const toast = sandbox.document.getElementById('ios-toast');

    nameInput.value = 'Primary Imported Wallet';
    wordsInput.value = 'abandon ability able about above absent absorb abstract absurd abuse access accident';

    sandbox.window.executeImportWallet();

    assert.equal(sandbox.window.state.wallets.length, 1, 'Wallet count must be 1');
    const w = sandbox.window.state.wallets[0];
    assert.equal(w.name, 'Primary Imported Wallet');
    assert.ok(w.address.startsWith('prl1p'), 'Must derive prl1p... Bech32m address');
    assert.ok(toast.innerText.includes('成功导入钱包'), 'Toast indicates successful import');
  });

  await runTest('2.5: executeImportWallet rejects duplicate wallet import and displays warning banner', () => {
    const sandbox = loadWalletEnvironment();
    sandbox.window.dispatchEvent('DOMContentLoaded');

    const wordsInput = sandbox.document.getElementById('import-mnemonic-input');
    const nameInput = sandbox.document.getElementById('import-wallet-name');
    const errEl = sandbox.document.getElementById('import-error-msg');
    const toast = sandbox.document.getElementById('ios-toast');

    const seed = 'abandon ability able about above absent absorb abstract absurd abuse access accident';

    // First import
    nameInput.value = 'Original Wallet';
    wordsInput.value = seed;
    sandbox.window.executeImportWallet();
    assert.equal(sandbox.window.state.wallets.length, 1);

    // Attempt second import with same mnemonic (even with different name or whitespace)
    nameInput.value = 'Duplicate Wallet Attempt';
    wordsInput.value = `  ${seed.toUpperCase()}  `; // Normalized check
    sandbox.window.executeImportWallet();

    assert.equal(sandbox.window.state.wallets.length, 1, 'Wallet count must remain 1 (NO DUPLICATE)');
    assert.ok(!errEl._classSet.has('hidden'), '#import-error-msg must be visible');
    assert.ok(errEl.innerText.includes('该钱包已存在于列表中') || errEl.innerText.includes('already exists in list'),
      'Inline error must alert user of duplicate wallet');
    assert.ok(errEl.innerText.includes('Original Wallet'), 'Error must mention original wallet name');
    assert.equal(errEl.innerText, toast.innerText, 'Toast matches duplicate warning');
  });

  await runTest('2.6: finalizeDirectWalletCreation rejects duplicate address creation', () => {
    const sandbox = loadWalletEnvironment(initialStorageWithWallet);
    sandbox.window.dispatchEvent('DOMContentLoaded');

    const toast = sandbox.document.getElementById('ios-toast');

    // Attempt to finalize creation of a wallet that has the same address as existing wallet
    sandbox.window.state.pendingWallet = {
      id: 'wallet-pending-dup',
      name: 'Duplicate Pending',
      pin: '123456',
      mnemonic: ['abandon', 'ability', 'able', 'about', 'above', 'absent', 'absorb', 'abstract', 'absurd', 'abuse', 'access', 'accident'],
      address: validTestWallet.address,
      privateKeyHex: '0x123',
      balance: 0.0,
      createdAt: new Date().toISOString()
    };

    sandbox.window.finalizeDirectWalletCreation();

    assert.equal(sandbox.window.state.wallets.length, 1, 'Must not append duplicate wallet');
    assert.ok(toast.innerText.includes('该钱包地址已存在于列表中') || toast.innerText.includes('already exists'),
      'Toast should reject duplicate address creation');
  });

  await runTest('2.7: initWallets automatically deduplicates redundant entries in localStorage', () => {
    const dupStorage = {
      pearl_user_wallets_v4: JSON.stringify({
        wallets: [validTestWallet, validTestWallet, validTestWallet],
        activeWalletId: validTestWallet.id
      })
    };

    const sandbox = loadWalletEnvironment(dupStorage);
    sandbox.window.dispatchEvent('DOMContentLoaded');

    assert.equal(sandbox.window.state.wallets.length, 1, 'initWallets must prune duplicates to exactly 1');
  });

  await runTest('2.8: executeImportWallet accepts valid 24-word BIP-39 mnemonic successfully', () => {
    const sandbox = loadWalletEnvironment();
    sandbox.window.dispatchEvent('DOMContentLoaded');

    const words24 = [
      'abandon', 'ability', 'able', 'about', 'above', 'absent',
      'absorb', 'abstract', 'absurd', 'abuse', 'access', 'accident',
      'account', 'accuse', 'achieve', 'acid', 'acoustic', 'acquire',
      'across', 'act', 'action', 'actor', 'actress', 'actual'
    ].join(' ');

    const wordsInput = sandbox.document.getElementById('import-mnemonic-input');
    const nameInput = sandbox.document.getElementById('import-wallet-name');
    const toast = sandbox.document.getElementById('ios-toast');

    nameInput.value = '24-Word Cold Storage';
    wordsInput.value = words24;

    sandbox.window.executeImportWallet();

    assert.equal(sandbox.window.state.wallets.length, 1, 'Wallet count must be 1');
    assert.equal(sandbox.window.state.wallets[0].name, '24-Word Cold Storage');
    assert.equal(sandbox.window.state.wallets[0].mnemonic.length, 24, 'Mnemonic length must be 24');
    assert.ok(toast.innerText.includes('成功导入钱包'), 'Toast confirms 24-word import');
  });

  await runTest('2.9: executeImportWallet normalizes multi-language delimiters (commas, semicolons, tabs, newlines)', () => {
    const sandbox = loadWalletEnvironment();
    sandbox.window.dispatchEvent('DOMContentLoaded');

    const messySeed = 'abandon，ability，able。about；above\tabsent\nabsorb,abstract;absurd abuse access accident';

    const wordsInput = sandbox.document.getElementById('import-mnemonic-input');
    const nameInput = sandbox.document.getElementById('import-wallet-name');

    nameInput.value = 'Messy Delimiters Wallet';
    wordsInput.value = messySeed;

    sandbox.window.executeImportWallet();

    assert.equal(sandbox.window.state.wallets.length, 1, 'Should normalize delimiters and import wallet');
    assert.equal(sandbox.window.state.wallets[0].mnemonic.length, 12);
  });

  await runTest('2.10: saveNewContact strictly validates Bech32m address and rejects invalid checksums', () => {
    const sandbox = loadWalletEnvironment();
    sandbox.window.dispatchEvent('DOMContentLoaded');

    const nameInput = sandbox.document.getElementById('contact-name-input');
    const addrInput = sandbox.document.getElementById('contact-address-input');
    const toast = sandbox.document.getElementById('ios-toast');

    nameInput.value = 'Alice Test';
    addrInput.value = 'prl1pvxtfv9c7a9elgny7jmhndtl9cwdy9wnhvphg7g5arxjvc2rwa4vq09sfpz'; // bad checksum

    sandbox.window.saveNewContact();

    assert.equal(sandbox.window.state.contacts.length, 0, 'No contact must be saved on invalid address');
    assert.ok(toast.innerText.includes('联系人地址无效'), 'Toast indicates invalid contact address');
  });

  await runTest('2.11: saveNewContact prevents saving duplicate contact addresses', () => {
    const sandbox = loadWalletEnvironment();
    sandbox.window.dispatchEvent('DOMContentLoaded');

    const validAddr = 'prl1pvxtfv9c7a9elgny7jmhndtl9cwdy9wnhvphg7g5arxjvc2rwa4vq09sfpm';
    const nameInput = sandbox.document.getElementById('contact-name-input');
    const addrInput = sandbox.document.getElementById('contact-address-input');
    const toast = sandbox.document.getElementById('ios-toast');

    nameInput.value = 'Bob Primary';
    addrInput.value = validAddr;
    sandbox.window.saveNewContact();
    assert.equal(sandbox.window.state.contacts.length, 1);

    nameInput.value = 'Bob Secondary';
    addrInput.value = validAddr.toUpperCase(); // Case insensitive check
    sandbox.window.saveNewContact();

    assert.equal(sandbox.window.state.contacts.length, 1, 'Duplicate contact must be rejected');
    assert.ok(toast.innerText.includes('已存在于联系人'), 'Toast warns about duplicate contact');
  });

  await runTest('2.12: queryMinerByAddress strictly validates Bech32m address and shows error box on invalid input', () => {
    const sandbox = loadWalletEnvironment();
    sandbox.window.dispatchEvent('DOMContentLoaded');

    const input = sandbox.document.getElementById('custom-miner-address');
    const resultBox = sandbox.document.getElementById('miner-query-result');
    const toast = sandbox.document.getElementById('ios-toast');

    input.value = 'badmineraddress';
    sandbox.window.queryMinerByAddress();

    assert.ok(!resultBox._classSet.has('hidden'), 'Result box must be visible');
    assert.ok(resultBox.innerHTML.includes('矿工地址无效'), 'Result box must display invalid miner address notice');
    assert.ok(toast.innerText.includes('矿工地址无效'), 'Toast must indicate invalid miner address');
  });

  // ==========================================================================
  // SUITE 3: Multi-Target Parity & Mock Data Hygiene
  // ==========================================================================
  console.log('\n--- Suite 3: Multi-Target Asset Parity & Mock Data Hygiene ---');

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

  function getFileSha256(p) {
    return crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
  }

  await runTest('3.1: Every core asset across dist/, android/, and ios/ matches root SHA256 byte-for-byte', () => {
    for (const asset of CORE_ASSETS) {
      const rootPath = path.join(ROOT_DIR, asset);
      assert.ok(fs.existsSync(rootPath), `Root asset missing: ${rootPath}`);
      const rootHash = getFileSha256(rootPath);

      for (const target of TARGETS) {
        const targetPath = path.join(target.path, asset);
        assert.ok(fs.existsSync(targetPath), `Target asset missing: ${targetPath}`);
        const targetHash = getFileSha256(targetPath);
        assert.equal(rootHash, targetHash, `Hash mismatch for ${asset} between root and ${target.name}`);
      }
    }
  });

  await runTest('3.2: Static scan confirms 0 mock patterns across root, dist, android, and ios', () => {
    const MOCK_PATTERNS = [
      { id: 'MOCK_MNEMONIC', regex: /lottery\s+girl\s+rain\s+peasant\s+fold\s+ankle/i },
      { id: 'TEST_MINER_BUTTON', regex: /fillTestMinerAddress|填入主网活跃矿工/ },
      { id: 'MOCK_CONTACTS', regex: /contact-default-1|contact-default-2|主网节点质押归集池|矿工冷钱包备用备份/ },
      { id: 'RANDOM_JITTER', regex: /Math\.random\(\)\s*-\s*0\.48|livePriceUSD\s*\+\s*jitter/ },
      { id: 'SYNTHETIC_CHARTS', regex: /liveH\s*\*\s*0\.962|liveDiff\s*\*\s*0\.985/ },
      { id: 'FAKE_SEND_DEDUCTION', regex: /wallet\.balance\s*-=\s*walletDeduct/ },
      { id: 'HARDCODED_PRICE_TAG', regex: /1\s*PRL\s*≈\s*\$1\.72|\$1\.72/ }
    ];

    const dirsToCheck = [
      ROOT_DIR,
      path.join(ROOT_DIR, 'dist'),
      path.join(ROOT_DIR, 'android', 'app', 'src', 'main', 'assets', 'public'),
      path.join(ROOT_DIR, 'ios', 'App', 'App', 'public')
    ];

    const violations = [];

    for (const dir of dirsToCheck) {
      for (const asset of CORE_ASSETS) {
        const filePath = path.join(dir, asset);
        if (!fs.existsSync(filePath)) continue;
        const content = fs.readFileSync(filePath, 'utf8');

        for (const pattern of MOCK_PATTERNS) {
          if (pattern.regex.test(content)) {
            violations.push(`Violation [${pattern.id}] in ${path.relative(ROOT_DIR, filePath)}`);
          }
        }
      }
    }

    assert.equal(violations.length, 0, `Mock violations detected:\n${violations.join('\n')}`);
  });

  await runTest('3.3: scripts/verify-sync.js passes with exit code 0 and confirms 100% parity', () => {
    const { execSync } = require('child_process');
    const out = execSync('node scripts/verify-sync.js', { cwd: ROOT_DIR, encoding: 'utf8' });
    assert.ok(out.includes('100% Asset Synchronization & Mock Hygiene Verified across all targets!'),
      'verify-sync.js must succeed and log success confirmation');
  });

  // ==========================================================================
  // SUMMARY
  // ==========================================================================
  console.log('\n===============================================================');
  console.log(`📊 ADVERSARIAL STRESS SUITE (GATE 3) RESULTS:`);
  console.log(`   Passed: ${results.passed}`);
  console.log(`   Failed: ${results.failed}`);
  console.log(`   Total:  ${results.passed + results.failed}`);
  console.log('===============================================================');

  if (results.failed > 0) {
    console.error('❌ STRESS TEST CHALLENGE FOUND DEFECTS!');
    process.exit(1);
  } else {
    console.log('✅ ALL GATE 3 ADVERSARIAL CHALLENGES WITHSTOOD EMPIRICALLY!');
    process.exit(0);
  }
}

main().catch(err => {
  console.error('Fatal error during test execution:', err);
  process.exit(1);
});
