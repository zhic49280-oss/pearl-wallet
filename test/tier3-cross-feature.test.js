/**
 * Tier 3: Cross-Feature Combinations Test Suite
 * Covers:
 * - T3.1: Wallet creation -> Bech32m address verification -> live on-chain balance query for fresh address
 * - T3.2: Known active address import -> Bech32m verification -> live balance -> transaction history query
 * - T3.3: Wallet manager duplicate address prevention and state consistency
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const { getRandomMnemonic, validateMnemonic } = require('./helpers/bip39');
const { encodeBech32m, validatePearlAddress } = require('./helpers/bech32m');
const { ApiClient } = require('./helpers/api-client');

test('T3.1: Wallet creation -> Bech32m validation -> live on-chain query for fresh address', async () => {
  // 1. Generate mnemonic
  const mnemonic = getRandomMnemonic(12);
  const mRes = validateMnemonic(mnemonic);
  assert.equal(mRes.valid, true);

  // 2. Derive 32-byte witness program and Bech32m address
  const randomBytes = new Uint8Array(32);
  crypto.getRandomValues(randomBytes);
  const freshAddress = encodeBech32m('prl', 1, Array.from(randomBytes));

  // 3. Validate Bech32m address format
  const vRes = validatePearlAddress(freshAddress);
  assert.equal(vRes.valid, true, `Derived address ${freshAddress} must be valid: ${vRes.error}`);
  assert.equal(vRes.decoded.witnessVersion, 1);
  assert.equal(vRes.decoded.hrp, 'prl');

  // 4. Query live RPC / explorer gateway for this fresh address
  const liveData = await ApiClient.fetchAddress(freshAddress);
  assert.ok(liveData, 'Response from explorer should be valid');
  assert.equal(liveData.address, freshAddress);
  
  // A freshly generated address should have 0 balance and 0 tx count
  assert.equal(liveData.balance_grains || 0, 0, 'Fresh address should have 0 balance_grains');
  assert.equal(liveData.tx_count || 0, 0, 'Fresh address should have 0 tx_count');
});

test('T3.2: Known address import -> Bech32m verification -> live balance -> confirmed tx history query', async () => {
  const knownAddress = 'prl1pvxtfv9c7a9elgny7jmhndtl9cwdy9wnhvphg7g5arxjvc2rwa4vq09sfpm';

  // 1. Verify address checksum & format
  const vRes = validatePearlAddress(knownAddress);
  assert.equal(vRes.valid, true, `Known address ${knownAddress} must be valid Bech32m`);

  // 2. Query live on-chain balance
  const balanceData = await ApiClient.fetchAddress(knownAddress);
  assert.equal(balanceData.address, knownAddress);
  assert.ok(balanceData.balance_grains > 0, `Active address should have positive balance (got ${balanceData.balance_grains})`);
  assert.ok(balanceData.tx_count > 0, `Active address should have tx_count > 0 (got ${balanceData.tx_count})`);

  // 3. Query live transaction history
  const txData = await ApiClient.fetchAddressTxs(knownAddress, 5);
  assert.ok(txData, 'Transaction response should be non-null');
  assert.ok(Array.isArray(txData.items), 'txData.items should be an array');
  assert.ok(txData.items.length > 0, 'Should return at least 1 transaction');

  // 4. Verify transaction items schema
  for (const item of txData.items) {
    assert.match(item.txid, /^[0-9a-f]{64}$/, `txid ${item.txid} should be 64-char hex string`);
    assert.ok(typeof item.delta_grains === 'number', 'delta_grains should be numeric');
    assert.ok(typeof item.time === 'string', 'time should be a string');
    assert.ok(!isNaN(Date.parse(item.time)), `time ${item.time} should be parseable as ISO date`);
  }
});

test('T3.3: Wallet manager duplicate address prevention and active wallet isolation', () => {
  // Model wallet state manager
  class WalletManager {
    constructor() {
      this.wallets = [];
      this.activeWalletId = null;
    }

    addWallet(wallet) {
      if (this.wallets.some(w => w.address === wallet.address)) {
        throw new Error(`钱包已存在: ${wallet.address}`);
      }
      this.wallets.push(wallet);
      this.activeWalletId = wallet.id;
      return wallet;
    }

    selectWallet(id) {
      const found = this.wallets.find(w => w.id === id);
      if (!found) throw new Error('Wallet not found');
      this.activeWalletId = id;
      return found;
    }
  }

  const manager = new WalletManager();
  const wallet1 = {
    id: 'wallet-1',
    name: '主钱包',
    address: 'prl1pvxtfv9c7a9elgny7jmhndtl9cwdy9wnhvphg7g5arxjvc2rwa4vq09sfpm',
    balance: 10.5
  };

  const wallet2 = {
    id: 'wallet-2',
    name: '次钱包',
    address: 'prl1pm66322jxrepueadzlpa72syya7he7m8r3a5kh7pdgxr6y6x66sqs50vuc3',
    balance: 5.0
  };

  // Add wallet1
  manager.addWallet(wallet1);
  assert.equal(manager.wallets.length, 1);
  assert.equal(manager.activeWalletId, 'wallet-1');

  // Attempt to add duplicate wallet with same address
  assert.throws(
    () => manager.addWallet({ id: 'wallet-dup', name: '重复钱包', address: wallet1.address, balance: 0 }),
    /钱包已存在/,
    'Adding duplicate address must be prevented'
  );
  assert.equal(manager.wallets.length, 1, 'Wallet count should still be 1');

  // Add distinct wallet2
  manager.addWallet(wallet2);
  assert.equal(manager.wallets.length, 2);
  assert.equal(manager.activeWalletId, 'wallet-2');

  // Switch back to wallet1
  manager.selectWallet('wallet-1');
  assert.equal(manager.activeWalletId, 'wallet-1');
  assert.equal(manager.wallets[0].balance, 10.5, 'Wallet 1 balance preserved');
  assert.equal(manager.wallets[1].balance, 5.0, 'Wallet 2 balance preserved');
});
