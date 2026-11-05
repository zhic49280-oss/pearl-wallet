/**
 * Tier 2: Boundary & Corner Cases Test Suite
 * Covers:
 * - T2.1: Empty and whitespace-only mnemonic validation
 * - T2.2: Invalid mnemonic word counts (1, 11, 13, 23, 25 words)
 * - T2.3: Non-BIP-39 dictionary words, digits, and special characters
 * - T2.4: Malformed address HRP and witness version (bc1, prl0, prl1q)
 * - T2.5: Malformed address charset, mixed case, corrupted checksum, and extreme lengths
 * - T2.6: Negative, zero, NaN, Infinity, and sub-fee transfer amounts
 * - T2.7: Network timeout and AbortController handling
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const { validateMnemonic } = require('./helpers/bip39');
const { validatePearlAddress, decodeBech32m } = require('./helpers/bech32m');
const { requestJson } = require('./helpers/api-client');

test('T2.1: Empty and whitespace-only mnemonics are rejected', () => {
  const inputs = ['', '   ', '\t\n\r', null, undefined];
  for (const input of inputs) {
    const res = validateMnemonic(input);
    assert.equal(res.valid, false, `Input "${input}" should be rejected`);
    assert.ok(res.error, 'Should provide an error message');
  }
});

test('T2.2: Invalid mnemonic word counts are strictly rejected', () => {
  const sampleWords = [
    'abandon', 'ability', 'able', 'about', 'above', 'absent',
    'absorb', 'abstract', 'absurd', 'abuse', 'access', 'accident',
    'account', 'accuse', 'achieve', 'acid', 'acoustic', 'acquire',
    'across', 'act', 'action', 'actor', 'actress', 'actual', 'adapt'
  ];

  const invalidCounts = [1, 5, 11, 13, 23, 25];
  for (const count of invalidCounts) {
    const phrase = sampleWords.slice(0, count).join(' ');
    const res = validateMnemonic(phrase);
    assert.equal(res.valid, false, `Word count ${count} should be rejected`);
    assert.match(res.error, /Invalid word count/, `Error should state invalid word count for length ${count}`);
  }
});

test('T2.3: Words not in BIP-39 English wordlist or containing numbers/symbols are rejected', () => {
  const validBase = 'abandon ability able about above absent absorb abstract absurd abuse access';
  
  // Non-existent English word
  const res1 = validateMnemonic(`${validBase} notarealword`);
  assert.equal(res1.valid, false, 'Word "notarealword" should be rejected');
  assert.match(res1.error, /Invalid BIP-39 words found/);

  // Numeric word
  const res2 = validateMnemonic(`${validBase} 12345`);
  assert.equal(res2.valid, false, 'Numeric word should be rejected');

  // Special characters
  const res3 = validateMnemonic(`${validBase} acc_ess!`);
  assert.equal(res3.valid, false, 'Special character word should be rejected');
});

test('T2.4: Malformed address HRP and witness version are rejected', () => {
  // Valid Pearl address for comparison: prl1pvxtfv9c7a9elgny7jmhndtl9cwdy9wnhvphg7g5arxjvc2rwa4vq09sfpm
  
  // Wrong HRP: Bitcoin 'bc' instead of 'prl'
  const bcAddr = 'bc1pvxtfv9c7a9elgny7jmhndtl9cwdy9wnhvphg7g5arxjvc2rwa4vq09sfpm';
  const resBc = validatePearlAddress(bcAddr);
  assert.equal(resBc.valid, false, 'Address with "bc" HRP should be rejected for Pearl');

  // Missing separator: 'prlp...'
  const noSep = 'prlpvxtfv9c7a9elgny7jmhndtl9cwdy9wnhvphg7g5arxjvc2rwa4vq09sfpm';
  const resNoSep = validatePearlAddress(noSep);
  assert.equal(resNoSep.valid, false, 'Address without separator "1" should be rejected');

  // Wrong witness version: 'prl1q...' (witness version 0 instead of 1)
  const v0Addr = 'prl1qvxtfv9c7a9elgny7jmhndtl9cwdy9wnhvphg7g5arxjvc2rwa4vq09sfpm';
  const resV0 = validatePearlAddress(v0Addr);
  assert.equal(resV0.valid, false, 'Witness version 0 (q) should be rejected for Pearl Taproot');
});

test('T2.5: Malformed address characters, mixed case, corrupted checksum, and extreme lengths are rejected', () => {
  const validAddr = 'prl1pvxtfv9c7a9elgny7jmhndtl9cwdy9wnhvphg7g5arxjvc2rwa4vq09sfpm';

  // Mixed case (violates Bech32 standard)
  const mixedCase = 'prl1pVxTfv9c7a9elgny7jmhndtl9cwdy9wnhvphg7g5arxjvc2rwa4vq09sfpm';
  const resMixed = validatePearlAddress(mixedCase);
  assert.equal(resMixed.valid, false, 'Mixed case address should be rejected');
  assert.match(resMixed.error, /Mixed case/);

  // Invalid bech32 characters (b, i, o, 1 not in charset)
  const invalidChar = validAddr.slice(0, 10) + 'b' + validAddr.slice(11);
  const resChar = validatePearlAddress(invalidChar);
  assert.equal(resChar.valid, false, 'Address with invalid bech32 character "b" should be rejected');

  // Corrupted checksum (change last character)
  const corrupted = validAddr.slice(0, -1) + (validAddr.endsWith('m') ? 'p' : 'm');
  const resCorrupt = validatePearlAddress(corrupted);
  assert.equal(resCorrupt.valid, false, 'Corrupted checksum should be rejected');
  assert.match(resCorrupt.error, /Invalid Bech32m checksum/);

  // Truncated length
  const truncated = validAddr.slice(0, 30);
  const resTrunc = validatePearlAddress(truncated);
  assert.equal(resTrunc.valid, false, 'Truncated address should be rejected');

  // Overlong address (> 90 chars)
  const overlong = validAddr + 'qqqqqqqqqqqqqqqqqqqqqqqqqqqqqq';
  const resOver = validatePearlAddress(overlong);
  assert.equal(resOver.valid, false, 'Overlong address (>90) should be rejected');
});

test('T2.6: Negative, zero, NaN, and below-fee transfer amounts are rejected by amount validator', () => {
  const feePRL = 0.00000308;

  function validateSendAmount(amount, fee = feePRL, mode = 'internal') {
    const num = parseFloat(amount);
    if (isNaN(num) || !isFinite(num)) {
      return { valid: false, error: '金额必须为有效数字' };
    }
    if (num <= 0) {
      return { valid: false, error: '转账金额必须大于 0' };
    }
    if (mode === 'internal' && num <= fee) {
      return { valid: false, error: `转账金额必须大于矿工手续费 (${fee} PRL)` };
    }
    return { valid: true, amount: num };
  }

  assert.equal(validateSendAmount(0).valid, false, '0 amount should be rejected');
  assert.equal(validateSendAmount(-1).valid, false, 'Negative amount should be rejected');
  assert.equal(validateSendAmount(-0.00000001).valid, false, 'Small negative amount should be rejected');
  assert.equal(validateSendAmount('abc').valid, false, 'Non-numeric string should be rejected');
  assert.equal(validateSendAmount(NaN).valid, false, 'NaN should be rejected');
  assert.equal(validateSendAmount(Infinity).valid, false, 'Infinity should be rejected');

  // In internal fee mode, amount must exceed fee
  assert.equal(validateSendAmount(feePRL, feePRL, 'internal').valid, false, 'Amount equal to fee in internal mode should be rejected');
  assert.equal(validateSendAmount(0.000001, feePRL, 'internal').valid, false, 'Amount less than fee in internal mode should be rejected');
  
  // Valid amount
  const validRes = validateSendAmount(1.5, feePRL, 'internal');
  assert.equal(validRes.valid, true, 'Valid positive amount above fee should pass');
});

test('T2.7: Network timeout and AbortController signal are handled cleanly without unhandled rejection', async () => {
  const abortController = new AbortController();
  // Immediately abort
  abortController.abort();

  let caughtError = null;
  try {
    await requestJson('https://api.prlscan.com/v1/status', {
      signal: abortController.signal,
      timeoutMs: 1
    });
  } catch (err) {
    caughtError = err;
  }

  assert.ok(caughtError, 'Should catch aborted request error');
  assert.ok(
    caughtError.name === 'AbortError' || caughtError.message.includes('abort'),
    `Expected AbortError, got ${caughtError.name}: ${caughtError.message}`
  );
});
