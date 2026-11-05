/**
 * BIP-39 Wordlist and Mnemonic Validation Helper
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');

let cachedWordlist = null;

function getWordlist() {
  if (cachedWordlist) return cachedWordlist;
  const filePath = path.resolve(__dirname, '../../bip39-wordlist.js');
  const code = fs.readFileSync(filePath, 'utf8');
  const sandbox = { window: {} };
  vm.createContext(sandbox);
  vm.runInContext(code, sandbox);
  cachedWordlist = sandbox.window.BIP39_WORDLIST;
  if (!Array.isArray(cachedWordlist) || cachedWordlist.length !== 2048) {
    throw new Error(`Expected 2048 words in BIP39_WORDLIST, found ${cachedWordlist ? cachedWordlist.length : 0}`);
  }
  return cachedWordlist;
}

function isValidWord(word) {
  if (!word || typeof word !== 'string') return false;
  const list = getWordlist();
  return list.includes(word.toLowerCase().trim());
}

function validateMnemonic(mnemonic) {
  if (!mnemonic || typeof mnemonic !== 'string') {
    return { valid: false, error: 'Mnemonic phrase must be a non-empty string' };
  }

  // Replace common delimiters (commas, fullstops, semicolons, tabs, newlines) with single space
  const cleaned = mnemonic.replace(/[,，.。;；\n\r\t]/g, ' ').trim();
  if (!cleaned) {
    return { valid: false, error: 'Mnemonic phrase cannot be empty' };
  }

  const words = cleaned.split(/\s+/);
  if (words.length !== 12 && words.length !== 24) {
    return { valid: false, error: `Invalid word count: expected 12 or 24 words, got ${words.length}` };
  }

  const wordlist = getWordlist();
  const wordSet = new Set(wordlist);
  const invalidWords = [];

  for (let i = 0; i < words.length; i++) {
    const w = words[i].toLowerCase();
    if (!/^[a-z]+$/.test(w) || !wordSet.has(w)) {
      invalidWords.push({ index: i + 1, word: words[i] });
    }
  }

  if (invalidWords.length > 0) {
    return {
      valid: false,
      error: `Invalid BIP-39 words found: ${invalidWords.map(x => `#${x.index} "${x.word}"`).join(', ')}`,
      invalidWords
    };
  }

  return { valid: true, words: words.map(w => w.toLowerCase()) };
}

function getRandomMnemonic(length = 12) {
  if (length !== 12 && length !== 24) {
    throw new Error('Mnemonic length must be 12 or 24');
  }
  const wordlist = getWordlist();
  const words = [];
  const randomBuf = new Uint32Array(length);
  crypto.getRandomValues(randomBuf);
  for (let i = 0; i < length; i++) {
    words.push(wordlist[randomBuf[i] % wordlist.length]);
  }
  return words.join(' ');
}

module.exports = {
  getWordlist,
  isValidWord,
  validateMnemonic,
  getRandomMnemonic
};
