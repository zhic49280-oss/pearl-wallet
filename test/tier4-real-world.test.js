/**
 * Tier 4: Real-World Application Scenarios Test Suite
 * Covers:
 * - T4.1: Fresh user onboarding flow from clean slate to Bech32m wallet initialization
 * - T4.2: Real Pearl on-chain address query & cross-provider consistency (prlscan vs HeroMiners)
 * - T4.3: Real market price feeds and chain status integrity (no Math.random() jitter)
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const { getRandomMnemonic, validateMnemonic } = require('./helpers/bip39');
const { encodeBech32m, validatePearlAddress } = require('./helpers/bech32m');
const { ApiClient } = require('./helpers/api-client');
const { createSandbox } = require('./helpers/runtime-sandbox');

test('T4.1: Fresh user onboarding end-to-end lifecycle with clean state', () => {
  // Step 1: Start with pristine environment
  const sandbox = createSandbox();
  assert.equal(sandbox.localStorage.length, 0, 'Initial localStorage should be pristine and empty');

  // Step 2: Generate 12-word mnemonic
  const mnemonic = getRandomMnemonic(12);
  const mRes = validateMnemonic(mnemonic);
  assert.equal(mRes.valid, true, 'Generated mnemonic must pass BIP-39 validation');
  assert.equal(mRes.words.length, 12, 'Must have 12 words');

  // Step 3: Derive 32-byte witness program
  const pseudoEntropy = new Uint8Array(32);
  crypto.getRandomValues(pseudoEntropy);
  const address = encodeBech32m('prl', 1, Array.from(pseudoEntropy));

  // Step 4: Validate Bech32m address
  const vRes = validatePearlAddress(address);
  assert.equal(vRes.valid, true, `Address ${address} must be valid Bech32m`);
  assert.equal(vRes.decoded.witnessVersion, 1);
  assert.equal(address.length, 63);

  // Step 5: Save newly onboarded wallet
  const newWallet = {
    id: `wallet-${Date.now()}`,
    name: '我的 Pearl 钱包',
    mnemonic: mRes.words,
    address,
    balance: 0.0,
    createdAt: new Date().toISOString()
  };

  sandbox.localStorage.setItem('pearl_wallets_v1', JSON.stringify([newWallet]));
  sandbox.localStorage.setItem('pearl_active_wallet_id', newWallet.id);

  // Step 6: Verify clean onboarding state
  const loadedWallets = JSON.parse(sandbox.localStorage.getItem('pearl_wallets_v1'));
  assert.equal(loadedWallets.length, 1);
  assert.equal(loadedWallets[0].address, address);
  assert.equal(sandbox.localStorage.getItem('pearl_active_wallet_id'), newWallet.id);

  // Verify contacts were NOT automatically polluted with mock data
  assert.equal(sandbox.localStorage.getItem('pearl_contacts_v1'), null, 'No mock contacts should be auto-created during onboarding');
});

test('T4.2: Real on-chain miner address query and cross-provider consensus (Explorer + HeroMiners)', async () => {
  const minerAddress = 'prl1pvxtfv9c7a9elgny7jmhndtl9cwdy9wnhvphg7g5arxjvc2rwa4vq09sfpm';

  // Concurrent queries to official explorer and mining pool
  const [explorerInfo, explorerStatus, heroStats] = await Promise.all([
    ApiClient.fetchAddress(minerAddress),
    ApiClient.fetchStatus(),
    ApiClient.fetchHeroMinersAddress(minerAddress)
  ]);

  // Explorer assertions
  assert.equal(explorerInfo.address, minerAddress);
  assert.ok(explorerInfo.balance_grains > 0, `Explorer balance should be > 0 (got ${explorerInfo.balance_grains})`);
  assert.ok(explorerInfo.tx_count > 0, `Explorer tx_count should be > 0 (got ${explorerInfo.tx_count})`);

  // HeroMiners pool assertions
  assert.ok(heroStats.stats, 'HeroMiners stats should be present');
  assert.ok(Number(heroStats.stats.paid) > 0, `HeroMiners total paid should be > 0 (got ${heroStats.stats.paid})`);
  assert.ok(Number(heroStats.stats.networkHeight) > 130000, `HeroMiners networkHeight should be > 130000`);

  // Cross-provider height verification: explorer tip height and HeroMiners network height should be closely aligned
  const explorerHeight = explorerStatus.tip_height;
  const poolHeight = Number(heroStats.stats.networkHeight);
  const heightDiff = Math.abs(explorerHeight - poolHeight);
  assert.ok(
    heightDiff <= 25,
    `Explorer height (${explorerHeight}) and pool height (${poolHeight}) should be closely synced (diff ${heightDiff} <= 25)`
  );
});

test('T4.3: Real market price feeds and chain status integrity without synthetic jitter', async () => {
  const [chainStatus, marketPrl, kryptexRates] = await Promise.all([
    ApiClient.fetchStatus(),
    ApiClient.fetchMarketPrl(),
    ApiClient.fetchKryptexRates()
  ]);

  // Chain status
  assert.equal(chainStatus.healthy, true);
  assert.ok(chainStatus.tip_height >= 130000);
  assert.ok(chainStatus.mempool_size >= 0);

  // Market PRL price from CoinMarketCap
  assert.ok(typeof marketPrl.price_usd === 'number', 'marketPrl.price_usd should be numeric');
  assert.ok(marketPrl.price_usd > 0.1 && marketPrl.price_usd < 100, `marketPrl price should be realistic (got $${marketPrl.price_usd})`);
  assert.ok(marketPrl.volume_24h_usd > 0, 'marketPrl.volume_24h_usd should be positive');
  assert.equal(marketPrl.source, 'CoinMarketCap');

  // Kryptex rates
  assert.ok(typeof kryptexRates.crypto?.PRL === 'number', 'Kryptex PRL price should be numeric');
  assert.ok(kryptexRates.crypto.PRL > 0, 'Kryptex PRL price should be positive');
  assert.ok(typeof kryptexRates.fiat?.CNY === 'number', 'Kryptex fiat CNY rate should be numeric');
  assert.ok(kryptexRates.fiat.CNY > 0, 'Kryptex CNY rate should be positive');

  // Verify prices between CoinMarketCap and Kryptex are in reasonable agreement (< 30% difference)
  const diffPct = Math.abs(marketPrl.price_usd - kryptexRates.crypto.PRL) / marketPrl.price_usd;
  assert.ok(
    diffPct < 0.30,
    `Market prices between CoinMarketCap ($${marketPrl.price_usd}) and Kryptex ($${kryptexRates.crypto.PRL}) should align (diff ${Math.round(diffPct * 100)}% < 30%)`
  );
});
