/**
 * scripts/sync-assets.js
 * Cross-Platform Web Asset Synchronizer & Mobile Build Hygiene Script
 *
 * Synchronizes root web application assets to:
 * 1. dist/ (Capacitor webDir & Web Distribution)
 * 2. android/app/src/main/assets/public/ (Android Capacitor runtime)
 * 3. ios/App/App/public/ (iOS Capacitor runtime)
 *
 * Zero external dependencies (Pure Node.js built-ins).
 * Works seamlessly across Windows, macOS, and Linux.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT_DIR = path.resolve(__dirname, '..');

// 7 Core Web Application Assets
const CORE_ASSETS = [
  'index.html',
  'app.js',
  'style.css',
  'bip39-wordlist.js',
  'qrcode.min.js',
  'manifest.json',
  'sw.js'
];

// Target Directories
const TARGET_DIRS = [
  {
    name: 'Web Distribution (dist/)',
    path: path.join(ROOT_DIR, 'dist'),
    isNative: false
  },
  {
    name: 'Android Assets (android/app/src/main/assets/public/)',
    path: path.join(ROOT_DIR, 'android', 'app', 'src', 'main', 'assets', 'public'),
    isNative: true
  },
  {
    name: 'iOS Assets (ios/App/App/public/)',
    path: path.join(ROOT_DIR, 'ios', 'App', 'App', 'public'),
    isNative: true
  }
];

function getFileHash(filePath) {
  const buf = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function syncAssets() {
  console.log('====================================================');
  console.log('🚀 Pearl Wallet Asset Synchronizer & Build Hygiene');
  console.log('====================================================');
  console.log(`Root source directory: ${ROOT_DIR}`);
  console.log(`Synchronizing ${CORE_ASSETS.length} core web assets...\n`);

  // 1. Verify all root assets exist
  for (const file of CORE_ASSETS) {
    const srcPath = path.join(ROOT_DIR, file);
    if (!fs.existsSync(srcPath)) {
      console.error(`❌ Missing required source file: ${srcPath}`);
      process.exit(1);
    }
  }

  let totalCopied = 0;
  let hasErrors = false;

  // 2. Synchronize to all 3 targets
  for (const target of TARGET_DIRS) {
    console.log(`📁 Target: ${target.name}`);

    try {
      fs.mkdirSync(target.path, { recursive: true });
    } catch (err) {
      console.error(`  ❌ Failed to create directory ${target.path}:`, err.message);
      hasErrors = true;
      continue;
    }

    for (const file of CORE_ASSETS) {
      const srcFile = path.join(ROOT_DIR, file);
      const destFile = path.join(target.path, file);

      try {
        fs.copyFileSync(srcFile, destFile);
        const srcHash = getFileHash(srcFile);
        const destHash = getFileHash(destFile);

        if (srcHash !== destHash) {
          console.error(`  ❌ Hash mismatch on ${file}!`);
          hasErrors = true;
        } else {
          const size = fs.statSync(destFile).size;
          console.log(`  ✔ ${file.padEnd(20)} [${(size / 1024).toFixed(1)} KB] -> Synced`);
          totalCopied++;
        }
      } catch (err) {
        console.error(`  ❌ Failed to copy ${file}:`, err.message);
        hasErrors = true;
      }
    }

    // Maintain native Capacitor bridge files
    if (target.isNative) {
      const bridgeFiles = ['cordova.js', 'cordova_plugins.js'];
      for (const bf of bridgeFiles) {
        const bfPath = path.join(target.path, bf);
        if (!fs.existsSync(bfPath)) {
          fs.writeFileSync(bfPath, '', 'utf8');
          console.log(`  ✔ ${bf.padEnd(20)} [Bridge Placeholder Created]`);
        }
      }
    }

    console.log('');
  }

  // 3. Synchronize capacitor.config.json if platform directories exist
  const rootCapConfig = path.join(ROOT_DIR, 'capacitor.config.json');
  if (fs.existsSync(rootCapConfig)) {
    const androidCapConfig = path.join(ROOT_DIR, 'android', 'app', 'src', 'main', 'assets', 'capacitor.config.json');
    if (fs.existsSync(path.dirname(androidCapConfig))) {
      fs.copyFileSync(rootCapConfig, androidCapConfig);
      console.log('✔ Synced capacitor.config.json -> android/app/src/main/assets/');
    }

    const iosCapConfig = path.join(ROOT_DIR, 'ios', 'App', 'App', 'capacitor.config.json');
    if (fs.existsSync(path.dirname(iosCapConfig))) {
      try {
        const rootJson = JSON.parse(fs.readFileSync(rootCapConfig, 'utf8'));
        rootJson.packageClassList = [];
        fs.writeFileSync(iosCapConfig, JSON.stringify(rootJson, null, '\t') + '\n', 'utf8');
        console.log('✔ Synced capacitor.config.json -> ios/App/App/');
      } catch (e) {
        fs.copyFileSync(rootCapConfig, iosCapConfig);
      }
    }
    console.log('');
  }

  if (hasErrors) {
    console.error('❌ Asset synchronization finished with errors.');
    process.exit(1);
  } else {
    console.log(`✅ Asset synchronization complete! Total files synchronized: ${totalCopied}`);
  }
}

if (require.main === module) {
  syncAssets();
}

module.exports = { syncAssets, CORE_ASSETS, TARGET_DIRS };
