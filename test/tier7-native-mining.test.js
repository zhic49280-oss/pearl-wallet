/**
 * test/tier7-native-mining.test.js
 * Feature 20: Native Mining Pool Dashboard & Zero External Redirects Test Suite
 *
 * Validates:
 * - T7.1: Subtab navigation ([概览] [矿池监控] [显卡对比] [经济模型]) updates styles & subview visibility
 * - T7.2: Kryptex live pool overview updates 4-grid metrics & PoUW cluster workers
 * - T7.3: GPU profitability calculator computes accurate daily PRL, power expense, and net profits
 * - T7.4: GPU benchmark table populates live comparison values
 * - T7.5: Miner address validation strictly protects query endpoint
 * - T7.6: In-app miner inquiry renders native cards with zero external redirects to pool.kryptex.com
 * - T7.7: Viral mining report generator formats shareable community text with address & profit stats
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

  const bip39Code = fs.readFileSync(path.join(ROOT_DIR, 'bip39-wordlist.js'), 'utf8');
  const appCode = fs.readFileSync(path.join(ROOT_DIR, 'app.js'), 'utf8');

  vm.createContext(sandbox.window);
  vm.runInContext(bip39Code, sandbox.window);
  vm.runInContext(appCode, sandbox.window);

  return sandbox;
}

test('T7.1: Subtab navigation ([概览] [矿池监控] [显卡对比] [经济模型]) updates styles & subview visibility', () => {
  const sandbox = initAppSandbox();
  const { document, window } = sandbox;

  assert.equal(typeof window.switchMiningSubTab, 'function', 'switchMiningSubTab must be exposed on window');

  // Switch to GPU subtab
  window.switchMiningSubTab('gpu');
  const gpuBtn = document.getElementById('subtab-mining-gpu');
  const gpuView = document.getElementById('mining-subview-gpu');
  const overviewView = document.getElementById('mining-subview-overview');

  assert.ok(gpuBtn.className.includes('bg-cyan-500/20'), 'Active subtab must have cyan active style');
  assert.ok(!gpuView.classList.contains('hidden'), 'GPU subview must not be hidden');
  assert.ok(overviewView.classList.contains('hidden'), 'Overview subview must be hidden');

  // Switch to Miner subtab
  window.switchMiningSubTab('miner');
  const minerBtn = document.getElementById('subtab-mining-miner');
  const minerView = document.getElementById('mining-subview-miner');
  assert.ok(minerBtn.className.includes('bg-cyan-500/20'));
  assert.ok(!minerView.classList.contains('hidden'));
  assert.ok(gpuView.classList.contains('hidden'));

  // Switch back to Overview
  window.switchMiningSubTab('overview');
  assert.ok(!overviewView.classList.contains('hidden'));
  assert.ok(minerView.classList.contains('hidden'));
});

test('T7.2: Kryptex live pool overview updates 4-grid metrics & PoUW cluster workers', async () => {
  const sandbox = initAppSandbox();
  const { document, window } = sandbox;

  // Mock fetchKryptexApi to return pool info
  window.fetchKryptexApi = async (path) => {
    if (path.includes('pool/info')) {
      return {
        net_hashrate: 92482656880362860000,
        workers: 103347,
        miners: 33148,
        estimated_profit_day: 1.12569e-14,
        block_reward: 2170.60,
        difficulty: { default: 59140000 }
      };
    }
    return {};
  };

  await window.fetchKryptexPoolOverview();

  const hashMetric = document.getElementById('overview-metric-hashrate');
  const unitMetric = document.getElementById('overview-metric-unit-daily');
  const diffMetric = document.getElementById('overview-metric-diff');
  const boardWorkers = document.getElementById('pool-active-workers');

  assert.ok(hashMetric.innerText.includes('92.48 EH/s'), `Expected 92.48 EH/s, got ${hashMetric.innerText}`);
  assert.ok(unitMetric.innerText.includes('11.26') || unitMetric.innerText.includes('11.27'), `Expected ~11.26/11.27 PRL/P·天, got ${unitMetric.innerText}`);
  assert.ok(diffMetric.innerText.includes('59.14M'), `Expected 59.14M difficulty, got ${diffMetric.innerText}`);
  assert.ok(boardWorkers.innerText.includes('103,347'), `Expected 103,347 workers, got ${boardWorkers.innerText}`);
});

test('T7.3: GPU profitability calculator computes accurate daily PRL, power expense, and net profits', () => {
  const sandbox = initAppSandbox();
  const { document, window } = sandbox;

  // Select RTX 4090 preset
  window.selectGpuPreset('4090');
  const hashInp = document.getElementById('gpu-calc-hash');
  const powerInp = document.getElementById('gpu-calc-power');
  assert.equal(Number(hashInp.value), 260.0);
  assert.equal(Number(powerInp.value), 350);

  // Set card count = 2
  const countInp = document.getElementById('gpu-calc-count');
  countInp.value = '2';
  window.calculateGpuProfit();

  const resultBox = document.getElementById('gpu-calc-result');
  assert.ok(resultBox.innerHTML.includes('520.00 TH/s'), 'Result must show 520.00 TH/s total hashrate');
  assert.ok(resultBox.innerHTML.includes('预估日产 PRL'), 'Result must show estimated daily PRL');
  assert.ok(resultBox.innerHTML.includes('每日纯净利'), 'Result must show daily net profit');

  // Also verify RTX 3080 preset (实测基准 102 TH/s)
  window.selectGpuPreset('3080');
  assert.equal(Number(hashInp.value), 102.0);
  assert.equal(Number(powerInp.value), 250);
});

test('T7.4: GPU benchmark table populates live comparison values', () => {
  const sandbox = initAppSandbox();
  const { document, window } = sandbox;

  window.renderGpuBenchmarkList();
  const table = document.getElementById('gpu-benchmark-table');
  assert.ok(table.innerHTML.includes('NVIDIA RTX 4090'), 'Benchmark table must include RTX 4090');
  assert.ok(table.innerHTML.includes('NVIDIA RTX 4080 Super'), 'Benchmark table must include RTX 4080');
  assert.ok(table.innerHTML.includes('AMD Radeon RX 7900 XTX'), 'Benchmark table must include RX 7900 XTX');
  assert.ok(table.innerHTML.includes('净利'), 'Benchmark table must include net profit stats');
});

test('T7.5: Miner address validation strictly protects query endpoint', () => {
  const sandbox = initAppSandbox();
  const { document, window } = sandbox;

  const input = document.getElementById('custom-miner-address');
  const resultBox = document.getElementById('miner-query-result');

  // Bad address
  input.value = 'invalid_pearl_address_123';
  window.queryMinerByAddress();

  assert.ok(!resultBox.classList.contains('hidden'), 'Result box must unhide on error');
  assert.ok(resultBox.innerHTML.includes('矿工地址无效'), 'Must alert invalid miner address');
});

test('T7.6: In-app miner inquiry renders native cards with zero external redirects to pool.kryptex.com', async () => {
  const sandbox = initAppSandbox();
  const { document, window } = sandbox;

  const input = document.getElementById('custom-miner-address');
  const resultBox = document.getElementById('miner-query-result');

  input.value = VALID_PEARL_ADDR;

  // Mock Kryptex API responses
  window.fetchKryptexApi = async (apiPath) => {
    if (apiPath.includes('balance')) {
      return { total: 15.4, unconfirmed: 0.82, confirmed: 14.58 };
    }
    if (apiPath.includes('workers')) {
      return {
        results: [
          { worker: 'rig-4090-x2', status: 'online', avg_hashrate_24h: '185460000000000', avg_hashrate_30m: '185460000000000', agent: 'OneZeroMiner/1.8.5', valid: 1520 }
        ]
      };
    }
    if (apiPath.includes('payouts')) {
      return {
        results: [
          { amount: '5.2000', date: '1794625730', txid: '2cc967148f0b853155f95cf220843f803c44b90f0ffa9de973e471be0e36dad9', status: 'PAID' }
        ]
      };
    }
    if (apiPath.includes('pool/info')) {
      return { estimated_profit_day: 1.1257e-14, block_reward: 2170.60 };
    }
    return {};
  };

  window.selectMinerPool('kryptex');
  window.queryMinerByAddress();

  // Wait microtask tick
  await new Promise(resolve => setTimeout(resolve, 50));

  // Must render native cards
  assert.ok(resultBox.innerHTML.includes('日净利 · 链上实收'), 'Must render native profit card');
  assert.ok(resultBox.innerHTML.includes('我的设备 (Workers)'), 'Must render native workers card');
  assert.ok(resultBox.innerHTML.includes('rig-4090-x2'), 'Must display active worker name');
  assert.ok(resultBox.innerHTML.includes('矿池自动打款记录 (Payouts)'), 'Must render native payouts card');
  assert.ok(resultBox.innerHTML.includes('一键复制今日挖矿收益战报'), 'Must include viral share report button');

  // Crucial: Must NOT contain external redirect link to pool.kryptex.com
  assert.ok(!resultBox.innerHTML.includes('pool.kryptex.com/prl/miner/stats'), 'Must zero out external redirect link to pool.kryptex.com');
});

test('T7.7: Viral mining report generator formats shareable community text with address & profit stats', () => {
  const sandbox = initAppSandbox();
  const { window } = sandbox;

  let copiedText = '';
  sandbox.window.navigator.clipboard = {
    writeText: async (text) => {
      copiedText = text;
      return true;
    }
  };

  window.shareMinerReport(VALID_PEARL_ADDR, '185.46 TH/s', '2.1', '3.12');
  assert.ok(copiedText.includes('Pearl (PRL) 矿工今日收益战报'), 'Report must have title header');
  assert.ok(copiedText.includes('185.46 TH/s'), 'Report must include hashrate');
  assert.ok(copiedText.includes('2.1 PRL'), 'Report must include daily PRL');
  assert.ok(copiedText.includes('免上小所一键跨链换 USDT'), 'Report must highlight in-wallet cross-chain swap feature');
});

test('T7.8: GPU presets calibration and TH/s unit integrity (RTX 3080 @ 102 TH/s, 4060Ti @ 92 TH/s)', () => {
  const sandbox = initAppSandbox();
  const { document, window } = sandbox;

  // 1. Verify TH/s unit in index.html template statically
  const indexHtml = fs.readFileSync(path.resolve(__dirname, '../index.html'), 'utf8');
  assert.ok(indexHtml.includes('单卡算力 (TH/s)'), 'index.html must display TH/s in label');
  assert.ok(indexHtml.includes('NVIDIA RTX 3080 (102 TH/s'), 'index.html must include RTX 3080 with 102 TH/s');
  assert.ok(indexHtml.includes('NVIDIA RTX 4060 Ti (92 TH/s'), 'index.html must include RTX 4060 Ti with 92 TH/s');
  assert.ok(indexHtml.includes('NVIDIA RTX 4090 (260 TH/s'), 'index.html must include RTX 4090 with 260 TH/s');

  // 2. Verify RTX 3080 calibrated preset
  window.selectGpuPreset('3080');
  const hashInp = document.getElementById('gpu-calc-hash');
  const powerInp = document.getElementById('gpu-calc-power');
  assert.equal(Number(hashInp.value), 102.0, 'RTX 3080 must be calibrated to 102.0 TH/s');
  assert.equal(Number(powerInp.value), 250, 'RTX 3080 power must be 250W');

  // 3. Verify RTX 4060 Ti calibrated preset
  window.selectGpuPreset('4060ti');
  assert.equal(Number(hashInp.value), 92.0, 'RTX 4060 Ti must be calibrated to 92.0 TH/s');
  assert.equal(Number(powerInp.value), 160, 'RTX 4060 Ti power must be 160W');

  // 4. Verify RTX 4090 calibrated preset
  window.selectGpuPreset('4090');
  assert.equal(Number(hashInp.value), 260.0, 'RTX 4090 must be calibrated to 260.0 TH/s');
  assert.equal(Number(powerInp.value), 350, 'RTX 4090 power must be 350W');
});

test('T7.9: Multi-format wallet import (address watch-only & candidate derivation)', async () => {
  const sandbox = initAppSandbox();
  const { document, window } = sandbox;

  // 1. Direct address import (e.g. miner address prl1p...)
  window.startImportWalletFlow();
  const wordsInput = document.getElementById('import-mnemonic-input');
  wordsInput.value = VALID_PEARL_ADDR;

  await window.executeImportWallet();
  const activeW = window.state.wallets.find(w => w.id === window.state.activeWalletId);
  assert.ok(activeW, 'Wallet must be imported and active');
  assert.equal(activeW.address, VALID_PEARL_ADDR, 'Imported address must match input address exactly');

  // 2. Candidate derivation paths verification
  const testWords = ["abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "about"];
  const candidates = window.deriveCandidateAddresses(testWords);
  assert.ok(Array.isArray(candidates), 'Candidates must be an array');
  assert.ok(candidates.length >= 4, 'Must have at least 4 candidate derivation paths');
  const bip86Pearl = candidates.find(c => c.path === "m/86'/808276'/0'/0/0");
  assert.ok(bip86Pearl, 'Must include Pearl BIP-86 path');
  assert.ok(bip86Pearl.address.startsWith('prl1p'), 'Candidate address must start with prl1p');
});
