/**
 * test/near-swap.test.js
 * Feature 19: NEAR Intents / Defuse Protocol Cross-Chain Swap Test Suite
 *
 * Validates:
 * - T6.1: Swap state initialization and multi-chain tokens catalog
 * - T6.2: Bidirectional swap controls (sell PRL / buy PRL) and token selection
 * - T6.3: Slippage tolerance configuration and precision base-unit conversions
 * - T6.4: Window global functions exposure for DOM and native event dispatchers
 * - T6.5: Live public Defuse/NEAR Intents tokens oracle reachability
 * - T6.6: Direct wallet payment prefill and navigation flow
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const ROOT_DIR = path.resolve(__dirname, '..');
const { createSandbox } = require('./helpers/runtime-sandbox');

const VALID_PEARL_ADDR = 'prl1pvxtfv9c7a9elgny7jmhndtl9cwdy9wnhvphg7g5arxjvc2rwa4vq09sfpm';

function initAppSandbox(initialStorage = {}) {
  const sandbox = createSandbox(initialStorage);
  sandbox.window.window = sandbox.window;
  sandbox.window.globalThis = sandbox.window;
  sandbox.window.scrollTo = () => {};
  sandbox.window.requestAnimationFrame = (cb) => setTimeout(cb, 0);
  sandbox.window.cancelAnimationFrame = (id) => clearTimeout(id);
  sandbox.window.AbortController = globalThis.AbortController;
  sandbox.window.fetch = globalThis.fetch || (async () => ({
    ok: true,
    status: 200,
    json: async () => ({})
  }));

  const bip39Code = fs.readFileSync(path.join(ROOT_DIR, 'bip39-wordlist.js'), 'utf8');
  const appCode = fs.readFileSync(path.join(ROOT_DIR, 'app.js'), 'utf8');

  vm.createContext(sandbox.window);
  vm.runInContext(bip39Code, sandbox.window);
  vm.runInContext(appCode, sandbox.window);

  return sandbox;
}

test('T6.1: Swap state initialization and multi-chain tokens catalog', () => {
  const sandbox = initAppSandbox({
    'pearl_user_wallets_v4': JSON.stringify({
      wallets: [{
        id: 'w_test',
        name: 'Swap Test Wallet',
        address: VALID_PEARL_ADDR,
        balance: 50.0
      }],
      activeWalletId: 'w_test'
    })
  });

  const state = sandbox.window.state;
  assert.ok(state.nearSwap, 'state.nearSwap must be initialized');
  assert.equal(state.nearSwap.direction, 'sell', 'Default swap direction should be sell PRL');
  assert.ok(Array.isArray(state.nearSwap.tokensList), 'tokensList must be an array');
  assert.ok(state.nearSwap.tokensList.length >= 6, 'Should support at least 6 popular multi-chain tokens');

  const symbols = state.nearSwap.tokensList.map(t => t.symbol);
  assert.ok(symbols.includes('USDT'), 'Must support USDT');
  assert.ok(symbols.includes('USDC'), 'Must support USDC');
  assert.ok(symbols.includes('NEAR'), 'Must support NEAR');
  assert.ok(symbols.includes('ETH'), 'Must support ETH');
  assert.ok(symbols.includes('SOL'), 'Must support SOL');
  assert.ok(symbols.includes('BTC'), 'Must support BTC');
});

test('T6.2: Bidirectional swap controls (sell PRL / buy PRL) and token selection', () => {
  const sandbox = initAppSandbox();
  const { setSwapDirection, toggleSwapDirection, selectSwapTargetToken, state } = sandbox.window;

  assert.equal(typeof setSwapDirection, 'function', 'setSwapDirection must be a function');
  assert.equal(typeof toggleSwapDirection, 'function', 'toggleSwapDirection must be a function');
  assert.equal(typeof selectSwapTargetToken, 'function', 'selectSwapTargetToken must be a function');

  setSwapDirection('buy');
  assert.equal(state.nearSwap.direction, 'buy', 'Direction should change to buy');

  toggleSwapDirection();
  assert.equal(state.nearSwap.direction, 'sell', 'Direction should toggle back to sell');

  const targetAssetId = 'nep141:base-0x833589fcd6edb6e08f4c7c32d4f71b54bda02913.omft.near';
  selectSwapTargetToken(targetAssetId);
  assert.equal(state.nearSwap.targetTokenId, targetAssetId, 'Target token must be updated');
});

test('T6.3: Slippage tolerance configuration and precision calculation', () => {
  const sandbox = initAppSandbox();
  const { setSwapSlippage, state } = sandbox.window;

  assert.equal(typeof setSwapSlippage, 'function', 'setSwapSlippage must be a function');
  setSwapSlippage(200);
  assert.equal(state.nearSwap.slippageTolerance, 200, 'Slippage must be set to 200 bps (2.0%)');

  setSwapSlippage(50);
  assert.equal(state.nearSwap.slippageTolerance, 50, 'Slippage must be set to 50 bps (0.5%)');
});

test('T6.4: Window global functions exposure for DOM and native event dispatchers', () => {
  const sandbox = initAppSandbox();
  const requiredFns = [
    'openNearSwapSheet',
    'closeNearSwapSheet',
    'setSwapDirection',
    'toggleSwapDirection',
    'selectSwapTargetToken',
    'handleSwapAmountInput',
    'setSwapMaxAmount',
    'handleSwapRecipientInput',
    'pasteToSwapRecipient',
    'setSwapSlippage',
    'executeNearSwap',
    'copySwapDepositAddress',
    'copySwapMemo',
    'paySwapWithCurrentWallet',
    'openNearOfficialSwap',
    'resetSwapForm',
    'switchNearSwapMode',
    'pasteToSwapTxHash',
    'submitSwapDepositTxHash'
  ];

  for (const fn of requiredFns) {
    assert.equal(
      typeof sandbox.window[fn],
      'function',
      `window.${fn} must be exposed as a callable function`
    );
  }
});

test('T6.5: Live public Defuse/NEAR Intents tokens oracle reachability', async () => {
  const res = await fetch('https://1click.chaindefuser.com/v0/tokens');
  assert.equal(res.status, 200, 'Tokens endpoint must return HTTP 200');
  const tokens = await res.json();
  assert.ok(Array.isArray(tokens), 'Tokens response must be an array');

  const prlToken = tokens.find(t => t.symbol === 'PRL' && t.blockchain === 'prl');
  assert.ok(prlToken, 'Must find registered Pearl token on NEAR Intents');
  assert.equal(prlToken.assetId, 'nep141:prl.omft.near', 'PRL assetId must match official registration');
  assert.equal(prlToken.decimals, 8, 'PRL decimals must be 8');
  assert.ok(typeof prlToken.price === 'number' && prlToken.price > 0, 'PRL must have authentic positive live price');
});

test('T6.6: Direct wallet payment prefill and navigation flow', () => {
  const sandbox = initAppSandbox({
    'pearl_user_wallets_v4': JSON.stringify({
      wallets: [{
        id: 'w_active',
        name: 'Active Pearl Wallet',
        address: VALID_PEARL_ADDR,
        balance: 100.0
      }],
      activeWalletId: 'w_active'
    })
  });

  const { state, paySwapWithCurrentWallet } = sandbox.window;
  const mockDepositAddr = 'prl1pvxtfv9c7a9elgny7jmhndtl9cwdy9wnhvphg7g5arxjvc2rwa4vq09sfpm';

  state.nearSwap.activeOrder = {
    depositAddress: mockDepositAddr,
    amountIn: '10.5',
    amountOut: '16.2',
    originSymbol: 'PRL',
    destSymbol: 'USDT'
  };

  assert.doesNotThrow(() => {
    paySwapWithCurrentWallet();
  }, 'paySwapWithCurrentWallet must execute cleanly');
});

test('T6.7: Bilingual switching converts nav bar, settings page labels, and counts cleanly between zh and en', () => {
  const sandbox = initAppSandbox({
    'pearl_user_wallets_v4': JSON.stringify({
      wallets: [{
        id: 'w_test_lang',
        name: 'Test Wallet',
        address: VALID_PEARL_ADDR,
        balance: 12.34
      }],
      activeWalletId: 'w_test_lang'
    })
  });

  const { setAppLanguage, state } = sandbox.window;

  // Switch to English
  setAppLanguage('en');
  assert.equal(state.currentLang, 'en', 'Current language must be en');

  const tabSwap = sandbox.document.querySelector('#tab-btn-swap span');
  assert.equal(tabSwap.innerText, 'Swap', 'Bottom tab #tab-btn-swap must display Swap in English');

  const devFeeLabel = sandbox.document.getElementById('dev-fee-status-label');
  assert.ok(
    devFeeLabel.innerText.includes('Enabled') || devFeeLabel.innerText.includes('Disabled'),
    `devFeeLabel should be English in en mode, got: ${devFeeLabel.innerText}`
  );

  const walletsCount = sandbox.document.getElementById('settings-wallets-count');
  assert.ok(
    walletsCount.innerText.includes('Active Wallet'),
    `settings-wallets-count should say Active Wallets, got: ${walletsCount.innerText}`
  );

  // Switch back to Chinese
  setAppLanguage('zh');
  assert.equal(state.currentLang, 'zh', 'Current language must be zh');
  assert.equal(tabSwap.innerText, '闪兑', 'Bottom tab #tab-btn-swap must display 闪兑 in Chinese');
  assert.ok(
    devFeeLabel.innerText.includes('已开启') || devFeeLabel.innerText.includes('已停用'),
    `devFeeLabel should be Chinese in zh mode, got: ${devFeeLabel.innerText}`
  );
});

test('T6.8: Active swap order rendering with foreign tx hash submission and mode switching', async () => {
  const sandbox = initAppSandbox({
    'pearl_user_wallets_v4': JSON.stringify({
      wallets: [{
        id: 'w_swap',
        name: 'Swap Wallet',
        address: VALID_PEARL_ADDR,
        balance: 50.0
      }],
      activeWalletId: 'w_swap'
    })
  });

  const { switchNearSwapMode, submitSwapDepositTxHash, state } = sandbox.window;

  // Mode switching
  switchNearSwapMode('aggregator');
  const aggView = sandbox.document.getElementById('swap-mode-aggregator-view');
  assert.ok(!aggView.classList.contains('hidden'), 'Aggregator view should be visible in aggregator mode');

  switchNearSwapMode('intent');
  assert.ok(aggView.classList.contains('hidden'), 'Aggregator view should be hidden in intent mode');

  // Submit foreign tx hash
  state.nearSwap.activeOrder = {
    depositAddress: 'defuse.near',
    amountIn: '10',
    amountOut: '6.2',
    originSymbol: 'USDT',
    destSymbol: 'PRL'
  };

  const hashInput = sandbox.document.getElementById('swap-tx-hash-input');
  hashInput.value = '4V78PsqYv3qfN7K9Z9aW9m2Q7x9F8s4d';

  await submitSwapDepositTxHash();

  const pill = sandbox.document.getElementById('swap-order-status-pill');
  assert.ok(
    pill.innerText.includes('充值凭证已提交') || pill.innerText.includes('已确认'),
    `Order status pill should update on submit, got: ${pill.innerText}`
  );
});
