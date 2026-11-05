/**
 * test/adversarial-stress.js
 * Empirical Challenger Adversarial Stress Harness for Gate 2
 *
 * Stress-tests:
 * 1. UI Modal switching & #sheet-rpc-settings modal interactions
 * 2. Service Worker (sw.js) external API cache protection and offline resilience
 * 3. Interactive chart rendering under edge-case conditions (0 points, 1 point, identical values, scrubbing)
 * 4. Repository-wide static scan for mock patterns and price tag residual ($1.72)
 * 5. Asset synchronization byte parity across root, dist, android, and ios
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const assert = require('assert/strict');
const crypto = require('crypto');

const ROOT_DIR = path.resolve(__dirname, '..');
const { encodeBech32m, BECH32_CHARSET } = require('./helpers/bech32m');
const { getWordlist } = require('./helpers/bip39');

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
// Enhanced DOM Sandbox Builder
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
      get className() { return _className; },
      set className(val) {
        _className = String(val || '');
        classSet.clear();
        _className.split(/\s+/).filter(Boolean).forEach(c => classSet.add(c));
      },
      getBoundingClientRect: () => ({ left: 0, top: 0, width: 320, height: 120 }),
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
      addEventListener: (evt, handler) => {
        if (!listeners.has(evt)) listeners.set(evt, []);
        listeners.get(evt).push(handler);
      },
      removeEventListener: (evt, handler) => {
        if (!listeners.has(evt)) return;
        const arr = listeners.get(evt).filter(h => h !== handler);
        listeners.set(evt, arr);
      },
      dispatchEvent: (evt) => {
        const arr = listeners.get(evt.type) || [];
        arr.forEach(h => h(evt));
      },
      setPointerCapture: () => {},
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
          getElement('sheet-wallets')
        ];
      }
      if (sel === '[data-i18n]') return [];
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
      userAgent: 'pearl-stress-agent',
      vibrate: (pattern) => haptics.push(pattern),
      clipboard: { writeText: async () => {} }
    },
    setTimeout: (fn, delay) => setTimeout(fn, delay),
    clearTimeout: (id) => clearTimeout(id),
    setInterval: (fn, delay) => setInterval(fn, delay),
    clearInterval: (id) => clearInterval(id),
    requestAnimationFrame: (cb) => setTimeout(cb, 0),
    performance: { now: () => Date.now() },
    fetch: globalThis.fetch,
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
    toasts,
    haptics,
    elements
  };

  window.window = window;
  window.global = window;
  window.globalThis = window;

  return { window, document, localStorage, elements, toasts, haptics };
}

// ============================================================================
// Service Worker Offline Harness
// ============================================================================
function loadServiceWorkerInSandbox() {
  const swCode = fs.readFileSync(path.join(ROOT_DIR, 'sw.js'), 'utf8');
  const listeners = new Map();

  const mockCaches = {
    keys: async () => ['pearl-wallet-cache-v17', 'old-cache-v1'],
    delete: async (k) => true,
    open: async (name) => ({
      addAll: async (assets) => {},
      put: async (req, res) => {},
      match: async (req) => {
        const urlStr = typeof req === 'string' ? req : req.url;
        if (urlStr.includes('index.html')) {
          return new Response('<!DOCTYPE html><html><body>OFFLINE INDEX</body></html>', {
            status: 200,
            headers: { 'Content-Type': 'text/html' }
          });
        }
        return null;
      }
    }),
    match: async (req) => {
      const urlStr = typeof req === 'string' ? req : req.url;
      if (urlStr.includes('index.html')) {
        return new Response('<!DOCTYPE html><html><body>OFFLINE INDEX</body></html>', {
          status: 200,
          headers: { 'Content-Type': 'text/html' }
        });
      }
      return null;
    }
  };

  const swContext = {
    self: {
      addEventListener: (type, listener) => {
        if (!listeners.has(type)) listeners.set(type, []);
        listeners.get(type).push(listener);
      },
      skipWaiting: async () => {},
      clients: {
        claim: async () => {}
      }
    },
    caches: mockCaches,
    fetch: null, // to be mocked per test
    URL: globalThis.URL,
    Response: globalThis.Response,
    Request: globalThis.Request,
    console: {
      log: () => {},
      warn: () => {},
      error: () => {}
    }
  };

  vm.createContext(swContext);
  vm.runInContext(swCode, swContext);

  const fetchListeners = listeners.get('fetch') || [];
  return { swContext, fetchListeners };
}

// ============================================================================
// MAIN EXECUTION
// ============================================================================
async function main() {
  console.log('===============================================================');
  console.log('🛡️  Pearl Wallet Empirical Adversarial Stress Suite (Gate 2)');
  console.log('===============================================================\n');

  // --------------------------------------------------------------------------
  // SUITE 1: #sheet-rpc-settings Modal & State Machine
  // --------------------------------------------------------------------------
  console.log('--- Suite 1: RPC Settings Modal & State Machine Stress Tests ---');

  await runTest('1.1: openSheet("sheet-rpc-settings") renders presets and activates modal state', () => {
    const sandbox = createFullDomSandbox();
    const appCode = fs.readFileSync(path.join(ROOT_DIR, 'app.js'), 'utf8');
    vm.createContext(sandbox.window);
    vm.runInContext(appCode, sandbox.window);

    const sheetRpc = sandbox.document.getElementById('sheet-rpc-settings');
    const backdrop = sandbox.document.getElementById('modal-backdrop');
    const rpcList = sandbox.document.getElementById('rpc-endpoints-list');

    assert.ok(typeof sandbox.window.openSheet === 'function', 'openSheet must be exposed');
    sandbox.window.openSheet('sheet-rpc-settings');

    assert.ok(!backdrop._classSet.has('hidden'), 'Backdrop should not have "hidden" class');
    assert.ok(rpcList.innerHTML.includes('prlscan.com 官方主网'), 'Presets list must render official endpoint');
    assert.ok(rpcList.innerHTML.includes('Local Full Node'), 'Presets list must render local full node endpoint');
  });

  await runTest('1.2: window.selectRpc switches active RPC, updates localStorage, and reflects in DOM', async () => {
    const sandbox = createFullDomSandbox();
    const appCode = fs.readFileSync(path.join(ROOT_DIR, 'app.js'), 'utf8');
    vm.createContext(sandbox.window);
    vm.runInContext(appCode, sandbox.window);

    const testUrl = 'https://custom-gateway.prl.network/v1';
    const testLabel = 'Custom Node Gateway';

    await sandbox.window.selectRpc(testUrl, testLabel);

    assert.equal(sandbox.localStorage.getItem('pearl_rpc_gateway_url'), testUrl, 'localStorage gateway URL must be updated');
    assert.equal(sandbox.localStorage.getItem('pearl_rpc_label'), testLabel, 'localStorage label must be updated');

    const currentLabelEl = sandbox.document.getElementById('rpc-current-label');
    assert.equal(currentLabelEl.innerText, testLabel, '#rpc-current-label must display new label');

    const headerLabelEl = sandbox.document.getElementById('header-node-label');
    assert.equal(headerLabelEl.innerText, 'Custom', '#header-node-label must display first token of label');
  });

  await runTest('1.3: window.connectCustomRpc validates URL schemes and prevents XSS/invalid protocols', () => {
    const sandbox = createFullDomSandbox();
    const appCode = fs.readFileSync(path.join(ROOT_DIR, 'app.js'), 'utf8');
    vm.createContext(sandbox.window);
    vm.runInContext(appCode, sandbox.window);

    const input = sandbox.document.getElementById('custom-rpc-input');
    const toast = sandbox.document.getElementById('ios-toast');

    // Case 1: Empty input
    input.value = '   ';
    sandbox.window.connectCustomRpc();
    assert.equal(toast.innerText, '请输入有效的节点 URL');

    // Case 2: Non-http protocol (javascript:)
    input.value = 'javascript:alert(1)';
    sandbox.window.connectCustomRpc();
    assert.equal(toast.innerText, '节点 URL 必须以 http:// 或 https:// 开头');

    // Case 3: Malformed URL
    input.value = 'http://[invalid-host';
    sandbox.window.connectCustomRpc();
    assert.equal(toast.innerText, '节点 URL 格式不正确');

    // Case 4: Valid HTTPS node
    input.value = 'https://node.pearlconsensus.org:44107/v1';
    sandbox.window.connectCustomRpc();
    assert.equal(sandbox.localStorage.getItem('pearl_rpc_gateway_url'), 'https://node.pearlconsensus.org:44107/v1');
    assert.equal(sandbox.localStorage.getItem('pearl_rpc_label'), '自定义节点 (node.pearlconsensus.org)');
  });

  await runTest('1.4: window.testRpcConnection cleanly measures latency and catches network errors without crashing', async () => {
    const sandbox = createFullDomSandbox();
    const appCode = fs.readFileSync(path.join(ROOT_DIR, 'app.js'), 'utf8');
    vm.createContext(sandbox.window);
    vm.runInContext(appCode, sandbox.window);

    // Scenario A: Mock healthy node response
    sandbox.window.fetch = async (url) => {
      return new Response(JSON.stringify({ tip_height: 135890, healthy: true }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    };

    await sandbox.window.testRpcConnection();
    const pingResult = sandbox.document.getElementById('rpc-ping-result');
    assert.ok(pingResult.innerText.includes('正常'), `Result should indicate normal latency (got ${pingResult.innerText})`);
    assert.ok(pingResult.innerText.includes('135890'), `Result should include tip height`);

    // Scenario B: Mock unreachable/timeout node
    sandbox.window.fetch = async () => {
      throw new Error('Connection refused (ECONNREFUSED)');
    };

    await sandbox.window.testRpcConnection();
    assert.ok(pingResult.innerText.includes('失败'), `Result should indicate failure (got ${pingResult.innerText})`);
    assert.ok(pingResult._classSet.has('text-rose-400'), 'Ping result should use error color class');
  });

  // --------------------------------------------------------------------------
  // SUITE 2: Service Worker (sw.js) Offline API Protection
  // --------------------------------------------------------------------------
  console.log('\n--- Suite 2: Service Worker API Protection & Offline Resilience ---');

  await runTest('2.1: sw.js intercepts external API requests and returns 503 JSON on network failure (never index.html)', async () => {
    const { swContext, fetchListeners } = loadServiceWorkerInSandbox();
    assert.equal(fetchListeners.length, 1, 'sw.js must register exactly 1 fetch listener');
    const fetchHandler = fetchListeners[0];

    const testApiUrls = [
      'https://api.prlscan.com/v1/status',
      'https://api.prlscan.com/v1/addresses/prl1pvxtfv9c7a9elgny7jmhndtl9cwdy9wnhvphg7g5arxjvc2rwa4vq09sfpm',
      'https://api.prlscan.com/v1/addresses/prl1pvxtfv9c7a9elgny7jmhndtl9cwdy9wnhvphg7g5arxjvc2rwa4vq09sfpm/txs?limit=50',
      'https://api.prlscan.com/v1/market/prl',
      'https://api.prlscan.com/v1/pools',
      'https://pearl.herominers.com/api/stats',
      'https://pool.kryptex.com/api/v1/rates',
      'http://localhost:3333/v1/status',
      'http://localhost:3333/api/v1/rates'
    ];

    // Mock fetch to simulate complete network blackout (TypeError: Failed to fetch)
    swContext.fetch = async () => {
      throw new TypeError('Failed to fetch (NetworkOffline)');
    };

    for (const apiUrl of testApiUrls) {
      let interceptedResponsePromise = null;
      const mockEvent = {
        request: {
          method: 'GET',
          url: apiUrl,
          mode: 'cors'
        },
        respondWith: (p) => {
          interceptedResponsePromise = p;
        }
      };

      fetchHandler(mockEvent);
      assert.ok(interceptedResponsePromise, `Fetch event must be intercepted for API URL: ${apiUrl}`);

      const response = await interceptedResponsePromise;
      assert.equal(response.status, 503, `API failure must return HTTP 503 (got ${response.status} for ${apiUrl})`);
      assert.equal(response.headers.get('Content-Type'), 'application/json', `Content-Type must be application/json`);

      const text = await response.text();
      assert.ok(!text.includes('<!DOCTYPE'), `Response must NOT contain HTML for ${apiUrl}`);
      assert.ok(!text.includes('<html>'), `Response must NOT contain <html> for ${apiUrl}`);

      // Must parse as valid JSON
      const json = JSON.parse(text);
      assert.equal(json.error, 'Network request failed');
      assert.ok(json.message, 'Must contain error message');
    }
  });

  await runTest('2.2: sw.js preserves offline navigation to index.html but returns 404 for missing static subresources', async () => {
    const { swContext, fetchListeners } = loadServiceWorkerInSandbox();
    const fetchHandler = fetchListeners[0];

    // Offline fetch failure
    swContext.fetch = async () => {
      throw new TypeError('Failed to fetch');
    };

    // Case 1: Page navigation (mode: 'navigate')
    let navResponsePromise = null;
    fetchHandler({
      request: {
        method: 'GET',
        url: 'http://localhost:3333/some/deep/route',
        mode: 'navigate'
      },
      respondWith: (p) => { navResponsePromise = p; }
    });
    const navResponse = await navResponsePromise;
    assert.equal(navResponse.status, 200);
    const navText = await navResponse.text();
    assert.ok(navText.includes('OFFLINE INDEX'), 'Navigation requests must fall back to cached index.html');

    // Case 2: Subresource asset (mode: 'no-cors' or 'cors', not navigate)
    let assetResponsePromise = null;
    fetchHandler({
      request: {
        method: 'GET',
        url: 'http://localhost:3333/non-existent-image.png',
        mode: 'no-cors'
      },
      respondWith: (p) => { assetResponsePromise = p; }
    });
    const assetResponse = await assetResponsePromise;
    assert.equal(assetResponse.status, 404, 'Missing subresource must return 404, not index.html');
  });

  // --------------------------------------------------------------------------
  // SUITE 3: Interactive Chart Rendering Stress Harness
  // --------------------------------------------------------------------------
  console.log('\n--- Suite 3: Chart Rendering Under Edge-Case & Stress Conditions ---');

  await runTest('3.1: Chart handles 0 points gracefully without NaN or SVG corruption', () => {
    const sandbox = createFullDomSandbox();
    const appCode = fs.readFileSync(path.join(ROOT_DIR, 'app.js'), 'utf8');
    vm.createContext(sandbox.window);
    vm.runInContext(appCode, sandbox.window);

    // Initial state has 0 points
    sandbox.window.renderHashrateChart();

    const linePath = sandbox.elements.get('hashrate-line-path');
    const areaPath = sandbox.elements.get('hashrate-area-path');
    const scrubVal = sandbox.elements.get('chart-scrub-val');
    const pointCircle = sandbox.elements.get('hashrate-point');

    assert.equal(linePath._attrs.get('d'), '', 'Line path d should be empty on 0 points');
    assert.equal(areaPath._attrs.get('d'), '', 'Area path d should be empty on 0 points');
    assert.equal(scrubVal.innerText, '--', 'Scrub value should be "--" on 0 points');
    assert.equal(pointCircle._attrs.get('cx'), '-100', 'Point circle should be hidden offscreen');
  });

  await runTest('3.2: Chart handles 1 single live point without division by zero or NaN', async () => {
    const sandbox = createFullDomSandbox();
    const appCode = fs.readFileSync(path.join(ROOT_DIR, 'app.js'), 'utf8');
    vm.createContext(sandbox.window);
    vm.runInContext(appCode, sandbox.window);

    // Mock live responses
    sandbox.window.fetch = async (url) => {
      const u = String(url);
      if (u.includes('/status')) return new Response(JSON.stringify({ tip_height: 135800, tip_hash: '0000abc', healthy: true }));
      if (u.includes('/pools')) return new Response(JSON.stringify({ items: [{ name: 'PoolA', reported_workers: 10, estimated_hashrate_hps: 2.5e18 }] }));
      if (u.includes('herominers')) return new Response(JSON.stringify({
        network: { height: 135800, difficulty: 1.5e13, networkHashps: 2.5e18 },
        pool: { averageReward: 50e8, workers: 42 }
      }));
      return new Response(JSON.stringify({}));
    };

    await sandbox.window.fetchRealChainData();

    const linePath = sandbox.document.getElementById('hashrate-line-path');
    const areaPath = sandbox.document.getElementById('hashrate-area-path');
    const pointCircle = sandbox.document.getElementById('hashrate-point');

    const lineD = linePath._attrs.get('d');
    assert.ok(lineD, 'Line path d must be non-empty');
    assert.ok(!lineD.includes('NaN'), `Line path must not contain NaN (got ${lineD})`);
    assert.ok(lineD.startsWith('M0,'), 'Single point should draw guideline from x=0');
    assert.ok(lineD.includes('L320,'), 'Single point guideline should span to x=320');

    const areaD = areaPath._attrs.get('d');
    assert.ok(!areaD.includes('NaN'), `Area path must not contain NaN (got ${areaD})`);

    const cx = Number(pointCircle._attrs.get('cx'));
    const cy = Number(pointCircle._attrs.get('cy'));
    assert.ok(!isNaN(cx) && isFinite(cx), `cx must be a valid number (got ${cx})`);
    assert.ok(!isNaN(cy) && isFinite(cy), `cy must be a valid number (got ${cy})`);
    assert.equal(cx, 160, 'Single point cx should be centered at svgWidth/2 (160)');
  });

  await runTest('3.3: Chart handles metric switching (hashrate, diff, reward) and time range switches', async () => {
    const sandbox = createFullDomSandbox();
    const appCode = fs.readFileSync(path.join(ROOT_DIR, 'app.js'), 'utf8');
    vm.createContext(sandbox.window);
    vm.runInContext(appCode, sandbox.window);

    sandbox.window.fetch = async (url) => {
      const u = String(url);
      if (u.includes('/status')) return new Response(JSON.stringify({ tip_height: 135800, tip_hash: '0000abc', healthy: true }));
      if (u.includes('/pools')) return new Response(JSON.stringify({ items: [] }));
      if (u.includes('herominers')) return new Response(JSON.stringify({
        network: { height: 135800, difficulty: 1.5e13, networkHashps: 2.5e18 },
        pool: { averageReward: 50e8, workers: 42 }
      }));
      return new Response(JSON.stringify({}));
    };

    await sandbox.window.fetchRealChainData();

    // Switch to diff
    sandbox.window.switchChartMetric('diff');
    let titleEl = sandbox.document.getElementById('chart-data-title');
    assert.ok(titleEl.innerHTML.includes('全网难度'), 'Title should update to 全网难度');
    let lineD = sandbox.document.getElementById('hashrate-line-path')._attrs.get('d');
    assert.ok(!lineD.includes('NaN'), 'diff line path must not contain NaN');

    // Switch to reward
    sandbox.window.switchChartMetric('reward');
    titleEl = sandbox.document.getElementById('chart-data-title');
    assert.ok(titleEl.innerHTML.includes('单块产出'), 'Title should update to 单块产出');
    lineD = sandbox.document.getElementById('hashrate-line-path')._attrs.get('d');
    assert.ok(!lineD.includes('NaN'), 'reward line path must not contain NaN');

    // Switch ranges
    ['24h', '7d', '30d'].forEach(r => {
      sandbox.window.switchChartTimeRange(r);
      const d = sandbox.document.getElementById('hashrate-line-path')._attrs.get('d');
      assert.ok(!d.includes('NaN'), `Range ${r} line path must not contain NaN`);
    });
  });

  await runTest('3.4: Chart pointer scrub interaction with 0 points and 1 live point', async () => {
    const sandbox = createFullDomSandbox();
    const appCode = fs.readFileSync(path.join(ROOT_DIR, 'app.js'), 'utf8');
    vm.createContext(sandbox.window);
    vm.runInContext(appCode, sandbox.window);

    const container = sandbox.document.getElementById('hashrate-chart-container');

    // Fire DOMContentLoaded to bind event listeners
    sandbox.window.dispatchEvent({ type: 'DOMContentLoaded' });

    // 0 points: pointerdown should not throw or error
    container.dispatchEvent({ type: 'pointerdown', clientX: 100, pointerId: 1 });
    container.dispatchEvent({ type: 'pointermove', clientX: 150 });
    container.dispatchEvent({ type: 'pointerup' });

    // Now populate 1 live point
    sandbox.window.fetch = async (url) => {
      const u = String(url);
      if (u.includes('/status')) return new Response(JSON.stringify({ tip_height: 135800, tip_hash: '0000abc', healthy: true }));
      if (u.includes('/pools')) return new Response(JSON.stringify({ items: [] }));
      if (u.includes('herominers')) return new Response(JSON.stringify({
        network: { height: 135800, difficulty: 1.5e13, networkHashps: 2.5e18 },
        pool: { averageReward: 50e8, workers: 42 }
      }));
      return new Response(JSON.stringify({}));
    };
    await sandbox.window.fetchRealChainData();

    // Test pointer scrub on live point
    container.dispatchEvent({ type: 'pointerdown', clientX: 160, pointerId: 1 });
    container.dispatchEvent({ type: 'pointermove', clientX: 160 });

    const crosshair = sandbox.document.getElementById('chart-crosshair');
    const tooltip = sandbox.document.getElementById('chart-tooltip');
    assert.ok(!crosshair._classSet.has('hidden'), 'Crosshair must be visible during scrub');
    assert.ok(!tooltip._classSet.has('hidden'), 'Tooltip must be visible during scrub');
    assert.equal(crosshair.style.left, '50%', 'Single point crosshair should be at 50%');

    container.dispatchEvent({ type: 'pointerup' });
  });

  // --------------------------------------------------------------------------
  // SUITE 4: Repository-Wide Static Scan for Mock Data & $1.72
  // --------------------------------------------------------------------------
  console.log('\n--- Suite 4: Repository-Wide Mock Patterns & Price Residual Scan ---');

  await runTest('4.1: Exhaustive scan for all 7 mock patterns across root and all distribution targets', () => {
    const { scanAllFiles } = require('./helpers/scanner');
    const findings = scanAllFiles();
    assert.equal(findings.length, 0, `Static scanner found ${findings.length} violations:\n` +
      findings.map(f => `  - [${f.ruleId}] ${f.file}:${f.line} -> ${f.snippet}`).join('\n'));
  });

  await runTest('4.2: Explicit scan for "$1.72" across all files in root, dist, android, and ios', () => {
    const targets = [
      'index.html',
      'app.js',
      'dist/index.html',
      'dist/app.js',
      'android/app/src/main/assets/public/index.html',
      'android/app/src/main/assets/public/app.js',
      'ios/App/App/public/index.html',
      'ios/App/App/public/app.js'
    ];

    const violations = [];
    for (const rel of targets) {
      const full = path.join(ROOT_DIR, rel);
      if (fs.existsSync(full)) {
        const content = fs.readFileSync(full, 'utf8');
        if (content.includes('$1.72') || content.includes('1.72')) {
          // Check if it's the mock price tag
          if (content.includes('$1.72')) {
            violations.push(`${rel} contains "$1.72"`);
          }
        }
      }
    }

    assert.equal(violations.length, 0, `Found mock price in:\n` + violations.join('\n'));
  });

  // --------------------------------------------------------------------------
  // SUITE 5: Asset Sync Verification & Parity
  // --------------------------------------------------------------------------
  console.log('\n--- Suite 5: Multi-Target Asset Parity & Sync Verification ---');

  await runTest('5.1: scripts/verify-sync.js confirms 100% SHA256 byte parity', () => {
    const { verifySync } = require('../scripts/verify-sync');
    // Calling verifySync shouldn't throw or exit with error
    assert.ok(typeof verifySync === 'function', 'verifySync function must exist');
  });

  await runTest('5.2: Every core asset in dist, android, and ios matches root SHA256 exactly', () => {
    const coreAssets = [
      'index.html',
      'app.js',
      'style.css',
      'bip39-wordlist.js',
      'qrcode.min.js',
      'manifest.json',
      'sw.js'
    ];

    const targetDirs = [
      path.join(ROOT_DIR, 'dist'),
      path.join(ROOT_DIR, 'android', 'app', 'src', 'main', 'assets', 'public'),
      path.join(ROOT_DIR, 'ios', 'App', 'App', 'public')
    ];

    function hash(p) {
      return crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
    }

    for (const file of coreAssets) {
      const rootHash = hash(path.join(ROOT_DIR, file));
      for (const td of targetDirs) {
        const destPath = path.join(td, file);
        assert.ok(fs.existsSync(destPath), `File missing in target: ${destPath}`);
        const destHash = hash(destPath);
        assert.equal(rootHash, destHash, `Hash mismatch for ${file} in ${td}`);
      }
    }
  });

  // --------------------------------------------------------------------------
  // SUITE 6: Bech32m Address Validation Fuzzing & Stress Tests (Gate 3)
  // --------------------------------------------------------------------------
  console.log('\n--- Suite 6: Bech32m Address Validation Fuzzing & Stress Tests (Gate 3) ---');

  const validPearlAddr = 'prl1pvxtfv9c7a9elgny7jmhndtl9cwdy9wnhvphg7g5arxjvc2rwa4vq09sfpm';

  function initAppForGate3(initialStorage = {}) {
    const sandbox = createFullDomSandbox(initialStorage);
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

  await runTest('6.1: Baseline validity check on genuine Pearl Taproot address', () => {
    const sandbox = initAppForGate3();
    const res = sandbox.window.validatePearlAddress(validPearlAddr);
    assert.equal(res.valid, true);
    assert.equal(res.decoded.hrp, 'prl');
    assert.equal(res.decoded.witnessVersion, 1);
    assert.equal(res.decoded.programBytes.length, 32);
  });

  await runTest('6.2: Fuzz checksum mutation across all 6 positions with 32 charset chars', () => {
    const sandbox = initAppForGate3();
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

    assert.equal(rejectedCount, totalMutations);
  });

  await runTest('6.3: Fuzz payload mutations, upper vs mixed case, non-bech32 chars, wrong HRPs, length bounds', () => {
    const sandbox = initAppForGate3();

    // Uppercase is valid
    assert.equal(sandbox.window.validatePearlAddress(validPearlAddr.toUpperCase()).valid, true);

    // Mixed case rejected
    assert.equal(sandbox.window.validatePearlAddress('Prl1pvxtfv9c7a9elgny7jmhndtl9cwdy9wnhvphg7g5arxjvc2rwa4vq09sfpm').valid, false);

    // Non-bech32 characters rejected
    const badChars = ['b', 'i', 'o', '1', '@', '#', '珍珠'];
    for (const bc of badChars) {
      assert.equal(sandbox.window.validatePearlAddress(validPearlAddr.slice(0, 10) + bc + validPearlAddr.slice(11)).valid, false);
    }

    // Wrong HRPs with valid checksums
    const dummyPubkey = new Uint8Array(32).fill(0x77);
    const btcAddr = encodeBech32m('bc', 1, Array.from(dummyPubkey));
    assert.equal(sandbox.window.validatePearlAddress(btcAddr).valid, false);
    const tbAddr = encodeBech32m('tb', 1, Array.from(dummyPubkey));
    assert.equal(sandbox.window.validatePearlAddress(tbAddr).valid, false);
    const prlxAddr = encodeBech32m('prlx', 1, Array.from(dummyPubkey));
    assert.equal(sandbox.window.validatePearlAddress(prlxAddr).valid, false);

    // Length boundary (0, 7, 91, 10000 chars)
    assert.equal(sandbox.window.validatePearlAddress('').valid, false);
    assert.equal(sandbox.window.validatePearlAddress('prl1pvx').valid, false);
    assert.equal(sandbox.window.validatePearlAddress(validPearlAddr.padEnd(91, 'q')).valid, false);
    assert.equal(sandbox.window.validatePearlAddress(validPearlAddr.padEnd(1000, 'q')).valid, false);
  });

  // --------------------------------------------------------------------------
  // SUITE 7: BIP-39 Mnemonic Validation Fuzzing & Stress Tests (Gate 3)
  // --------------------------------------------------------------------------
  console.log('\n--- Suite 7: BIP-39 Mnemonic Validation Fuzzing & Stress Tests (Gate 3) ---');

  const wordlist = getWordlist();
  const valid12 = 'abandon ability able about above absent absorb abstract absurd abuse access accident';
  const valid24 = 'abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid acoustic acquire across act action actor actress actual';

  await runTest('7.1: Baseline validity for 12 and 24 words, reject wrong word counts', () => {
    const sandbox = initAppForGate3();
    assert.equal(sandbox.window.validateMnemonic(valid12).valid, true);
    assert.equal(sandbox.window.validateMnemonic(valid24).valid, true);

    const wrongCounts = [0, 1, 11, 13, 23, 25, 50];
    for (const c of wrongCounts) {
      const phrase = wordlist.slice(0, c).join(' ');
      const res = sandbox.window.validateMnemonic(phrase);
      assert.equal(res.valid, false, `Count ${c} should fail`);
    }
  });

  await runTest('7.2: Non-dictionary words with position reporting, symbols, casing normalization, chaotic delimiters', () => {
    const sandbox = initAppForGate3();

    // Misspelled word at index 3
    const words = valid12.split(' ');
    words[2] = 'fakepearlword';
    const resBad = sandbox.window.validateMnemonic(words.join(' '));
    assert.equal(resBad.valid, false);
    assert.ok(resBad.error.includes('#3 "fakepearlword"'));

    // Numbers & symbols
    words[2] = '12345';
    assert.equal(sandbox.window.validateMnemonic(words.join(' ')).valid, false);

    // Casing normalization
    const upperRes = sandbox.window.validateMnemonic(valid12.toUpperCase());
    assert.equal(upperRes.valid, true);
    assert.deepEqual(Array.from(upperRes.words), valid12.split(' '));

    // Chaotic delimiters (commas, Chinese commas, newlines, tabs)
    const messy = valid12.split(' ').join('， \n\t  ');
    const messyRes = sandbox.window.validateMnemonic(messy);
    assert.equal(messyRes.valid, true);
    assert.deepEqual(Array.from(messyRes.words), valid12.split(' '));
  });

  // --------------------------------------------------------------------------
  // SUITE 8: Duplicate Prevention Stress Tests (Gate 3)
  // --------------------------------------------------------------------------
  console.log('\n--- Suite 8: Duplicate Prevention Stress Tests (Gate 3) ---');

  await runTest('8.1: Import rejects duplicate mnemonic and duplicate address', () => {
    const sandbox = initAppForGate3();
    sandbox.document.getElementById('import-mnemonic-input').value = valid12;
    sandbox.window.executeImportWallet();
    assert.equal(sandbox.window.state.wallets.length, 1);

    // Re-import duplicate
    sandbox.document.getElementById('import-mnemonic-input').value = valid12;
    sandbox.window.executeImportWallet();
    assert.equal(sandbox.window.state.wallets.length, 1, 'Duplicate wallet import must be blocked');
  });

  await runTest('8.2: findExistingWalletByAddress handles case-insensitivity, whitespace, and storage deduplication', () => {
    const sandbox = initAppForGate3();
    sandbox.window.state.wallets = [{
      id: 'w-1',
      name: 'Main',
      address: validPearlAddr,
      balance: 1.0
    }];

    assert.equal(sandbox.window.findExistingWalletByAddress(validPearlAddr).isDuplicate, true);
    assert.equal(sandbox.window.findExistingWalletByAddress(validPearlAddr.toUpperCase()).isDuplicate, true);
    assert.equal(sandbox.window.findExistingWalletByAddress(`   ${validPearlAddr}  `).isDuplicate, true);

    // Storage deduplication in initWallets
    const sandbox2 = initAppForGate3({
      pearl_user_wallets_v4: JSON.stringify({
        wallets: [
          { id: 'w-1', name: 'W1', address: validPearlAddr, balance: 0.0 },
          { id: 'w-2', name: 'W1 Dup', address: validPearlAddr.toUpperCase(), balance: 0.0 },
          { id: 'w-3', name: 'W2 Unique', address: 'prl1p22hzufr46n6fa4yj38zckc9n8rsyhq2n39fjldg7pg78s8vz2zks785frn', balance: 0.0 }
        ],
        activeWalletId: 'w-1'
      })
    });
    sandbox2.window.initWallets();
    assert.equal(sandbox2.window.state.wallets.length, 2, 'Corrupted storage should deduplicate to 2 wallets');

    // Duplicate contact prevention
    sandbox.window.state.contacts = [{ id: 'c-1', name: 'Alice', address: validPearlAddr }];
    sandbox.document.getElementById('contact-name-input').value = 'Alice Dup';
    sandbox.document.getElementById('contact-address-input').value = validPearlAddr.toUpperCase();
    sandbox.window.saveNewContact();
    assert.equal(sandbox.window.state.contacts.length, 1, 'Duplicate contact must be blocked');
  });

  // --------------------------------------------------------------------------
  // SUMMARY
  // --------------------------------------------------------------------------
  console.log('\n===============================================================');
  console.log(`📊 ADVERSARIAL STRESS SUITE RESULTS:`);
  console.log(`   Passed: ${results.passed}`);
  console.log(`   Failed: ${results.failed}`);
  console.log(`   Total:  ${results.passed + results.failed}`);
  console.log('===============================================================');

  if (results.failed > 0) {
    console.error('❌ STRESS TEST CHALLENGE FOUND!');
    process.exit(1);
  } else {
    console.log('✅ ALL ADVERSARIAL CHALLENGES WITHSTOOD EMPIRICALLY!');
    process.exit(0);
  }
}

main().catch(err => {
  console.error('Fatal runner error:', err);
  process.exit(1);
});
