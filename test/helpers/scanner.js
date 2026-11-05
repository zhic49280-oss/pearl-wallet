/**
 * Static Codebase Scanner for Mock and Test Data
 * Checks for hardcoded test mnemonics, test miner addresses/buttons,
 * auto-injected mock contacts, synthetic charts, and fake send balance deductions.
 */

const fs = require('fs');
const path = require('path');

const ROOT_DIR = path.resolve(__dirname, '../../');

const SCAN_RULES = [
  {
    id: 'MOCK_MNEMONIC_PHRASE',
    description: 'Hardcoded test mnemonic phrase found in code/templates',
    pattern: /lottery\s+girl\s+rain\s+peasant\s+fold\s+ankle/i,
    files: ['app.js', 'index.html', 'server.js', 'manifest.json']
  },
  {
    id: 'TEST_MINER_BUTTON_OR_FUNCTION',
    description: 'Test miner address button or auto-fill function present',
    pattern: /fillTestMinerAddress|填入主网活跃矿工/,
    files: ['app.js', 'index.html']
  },
  {
    id: 'AUTO_SAVED_MOCK_CONTACTS',
    description: 'Hardcoded demonstration contacts auto-seeded into storage',
    pattern: /contact-default-1|contact-default-2|主网节点质押归集池|矿工冷钱包备用备份/,
    files: ['app.js']
  },
  {
    id: 'RANDOM_PRICE_JITTER',
    description: 'Synthetic price fluctuation via Math.random() jitter',
    pattern: /Math\.random\(\)\s*-\s*0\.48|livePriceUSD\s*\+\s*jitter/,
    files: ['app.js']
  },
  {
    id: 'SYNTHETIC_CHART_MULTIPLIERS',
    description: 'Hardcoded synthetic multiplier curves for historical charts',
    pattern: /liveH\s*\*\s*0\.962|liveDiff\s*\*\s*0\.985/,
    files: ['app.js']
  },
  {
    id: 'FAKE_SEND_STATE_MUTATION',
    description: 'Simulated send transaction mutating balance locally without RPC',
    pattern: /wallet\.balance\s*-=\s*walletDeduct/,
    files: ['app.js']
  },
  {
    id: 'HARDCODED_MOCK_PRICE',
    description: 'Hardcoded legacy mock price found in templates',
    pattern: /\$1\.72|1\s*PRL\s*≈\s*\$1\.72/,
    files: ['index.html']
  }
];

function scanFile(relPath, rules = SCAN_RULES) {
  const absPath = path.join(ROOT_DIR, relPath);
  if (!fs.existsSync(absPath)) return [];

  const content = fs.readFileSync(absPath, 'utf8');
  const lines = content.split('\n');
  const findings = [];

  for (const rule of rules) {
    if (!rule.files.includes(relPath)) continue;

    for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
      const line = lines[lineIndex];
      if (rule.pattern.test(line)) {
        findings.push({
          ruleId: rule.id,
          description: rule.description,
          file: relPath,
          line: lineIndex + 1,
          snippet: line.trim()
        });
      }
    }
  }

  return findings;
}

function scanAllFiles(rules = SCAN_RULES) {
  const allFindings = [];
  const scannedFiles = new Set();
  for (const rule of rules) {
    for (const f of rule.files) {
      if (!scannedFiles.has(f)) {
        scannedFiles.add(f);
        allFindings.push(...scanFile(f, rules));
      }
    }
  }
  return allFindings;
}

module.exports = {
  SCAN_RULES,
  scanFile,
  scanAllFiles
};
