/**
 * Clean In-Memory Browser Runtime Sandbox
 * Provides isolated localStorage, crypto, and window environment for testing
 * wallet lifecycle, storage persistence, and state transitions.
 */

class MockLocalStorage {
  constructor() {
    this.store = new Map();
  }

  getItem(key) {
    return this.store.has(key) ? this.store.get(key) : null;
  }

  setItem(key, value) {
    this.store.set(key, String(value));
  }

  removeItem(key) {
    this.store.delete(key);
  }

  clear() {
    this.store.clear();
  }

  get length() {
    return this.store.size;
  }

  key(index) {
    return Array.from(this.store.keys())[index] || null;
  }

  dump() {
    const obj = {};
    for (const [k, v] of this.store.entries()) {
      obj[k] = v;
    }
    return obj;
  }
}

function createSandbox(initialStorage = {}) {
  const localStorage = new MockLocalStorage();
  for (const [k, v] of Object.entries(initialStorage)) {
    localStorage.setItem(k, v);
  }

  const elements = new Map();

  function getOrCreateElement(id) {
    if (!elements.has(id)) {
      elements.set(id, {
        id,
        value: '',
        innerText: '',
        innerHTML: '',
        style: {},
        classList: {
          contains: () => false,
          add: () => {},
          remove: () => {},
          toggle: () => {}
        },
        setAttribute: () => {},
        getAttribute: () => null,
        addEventListener: () => {}
      });
    }
    return elements.get(id);
  }

  const document = {
    getElementById: (id) => getOrCreateElement(id),
    querySelector: (sel) => getOrCreateElement(sel),
    querySelectorAll: () => [],
    addEventListener: () => {},
    removeEventListener: () => {}
  };

  const window = {
    localStorage,
    document,
    crypto: {
      getRandomValues: (buf) => crypto.getRandomValues(buf)
    },
    navigator: {
      userAgent: 'pearl-test-agent',
      clipboard: {
        writeText: async () => {}
      }
    },
    addEventListener: () => {},
    removeEventListener: () => {},
    setTimeout: (fn, delay) => setTimeout(fn, delay),
    clearTimeout: (id) => clearTimeout(id),
    setInterval: (fn, delay) => setInterval(fn, delay),
    clearInterval: (id) => clearInterval(id)
  };

  return {
    window,
    document,
    localStorage,
    elements
  };
}

module.exports = {
  MockLocalStorage,
  createSandbox
};
