/**
 * Public Zero-Auth API Client for Pearl Blockchain & Mining Services
 */

const DEFAULT_TIMEOUT_MS = 10000;

async function requestJson(url, options = {}) {
  const timeoutMs = options.timeoutMs || DEFAULT_TIMEOUT_MS;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(url, {
      ...options,
      signal: options.signal || controller.signal,
      headers: {
        'Accept': 'application/json',
        ...(options.headers || {})
      }
    });

    if (!res.ok) {
      const err = new Error(`HTTP ${res.status}: ${res.statusText} at ${url}`);
      err.status = res.status;
      throw err;
    }

    const data = await res.json();
    return data;
  } finally {
    clearTimeout(timer);
  }
}

const ApiClient = {
  async fetchStatus(baseUrl = 'https://api.prlscan.com/v1', options = {}) {
    return requestJson(`${baseUrl}/status`, options);
  },

  async fetchAddress(address, baseUrl = 'https://api.prlscan.com/v1', options = {}) {
    return requestJson(`${baseUrl}/addresses/${encodeURIComponent(address)}`, options);
  },

  async fetchAddressTxs(address, limit = 50, baseUrl = 'https://api.prlscan.com/v1', options = {}) {
    return requestJson(`${baseUrl}/addresses/${encodeURIComponent(address)}/txs?limit=${limit}`, options);
  },

  async fetchMarketPrl(baseUrl = 'https://api.prlscan.com/v1', options = {}) {
    return requestJson(`${baseUrl}/market/prl`, options);
  },

  async fetchKryptexRates(baseUrl = 'https://pool.kryptex.com', options = {}) {
    return requestJson(`${baseUrl}/api/v1/rates`, options);
  },

  async fetchHeroMinersStats(baseUrl = 'https://pearl.herominers.com', options = {}) {
    return requestJson(`${baseUrl}/api/stats`, options);
  },

  async fetchHeroMinersAddress(address, baseUrl = 'https://pearl.herominers.com', options = {}) {
    return requestJson(`${baseUrl}/api/stats_address?address=${encodeURIComponent(address)}`, options);
  }
};

module.exports = {
  ApiClient,
  requestJson
};
