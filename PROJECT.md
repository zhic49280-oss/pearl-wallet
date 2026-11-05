# Project: pearl-walle (Pearl 珍珠币移动钱包)

## Architecture
- **Application Model**: Single-page mobile/PWA web wallet running in browser, PWA, and Capacitor 8.6.0 native wrappers (Android & iOS).
- **Core Technology**: Vanilla JavaScript (ES6+), HTML5, CSS3, Tailwind CSS CDN, BIP-39 wordlist, QRCode.js.
- **Blockchain Target**: Pearl (PRL), a Proof-of-Useful-Work (PoUW) Layer-1 blockchain forked from Bitcoin `btcd`.
  - Address format: Taproot Bech32m witness v1 (`prl1p...`).
  - Base denomination: 1 PRL = 10^8 grains.
- **Network Services**:
  - Primary Public Explorer REST API: `https://api.prlscan.com/v1` (Zero-Auth, CORS-enabled, High-Availability).
  - Mining Pool Stats & Rates: `https://pearl.herominers.com/api` and `https://pool.kryptex.com/api`.
  - Full Node RPC: `http://localhost:44107` (standard `pearld` consensus RPC).
- **Local Dev Server**: Node.js `server.js` listening on port `3333`.

## Feature Inventory
| # | Feature | Description | Milestone | Source | Status |
|---|---------|-------------|-----------|--------|--------|
| 1 | Clean Initial Contacts & LocalStorage | Remove hardcoded demo addresses auto-saved in `loadContacts()`; ensure clean initial state | M1 | Survey 1, 3 | DONE |
| 2 | Remove Test Miner Address & Button | Remove `fillTestMinerAddress` in `app.js` and test button in `index.html` | M1 | Survey 1, 2 | DONE |
| 3 | Clean Mnemonic Placeholder | Replace hardcoded 12-word seed placeholder in `index.html` with generic placeholder | M1 | Survey 1 | DONE |
| 4 | Remove Fake Send & Local State Mutation | Remove fake `wallet.balance -= walletDeduct` and mock `state.txHistory.unshift` in `executeSend()` | M1 | Survey 1, 2, 3 | DONE |
| 5 | Remove Random Price Jitter | Remove `Math.random()` synthetic price fluctuations in `app.js` | M1 | Survey 1, 2, 3 | DONE |
| 6 | Remove Synthetic Chart Multipliers | Remove hardcoded trend multipliers in `syncNetworkMetricsWithLiveChainData` | M1 | Survey 1, 2 | DONE |
| 7 | Clean Hardcoded Fallback Metrics | Remove hardcoded chain defaults and initialize with loading/empty state | M1 | Survey 1, 2, 3 | DONE |
| 8 | Real Address Balance Inquiry | Query `GET https://api.prlscan.com/v1/addresses/{addr}` for actual on-chain balance | M2 | Survey 2, 3 | DONE |
| 9 | Real Transaction History Inquiry | Query `GET https://api.prlscan.com/v1/addresses/{addr}/txs?limit=50` for confirmed tx history | M2 | Survey 2, 3 | DONE |
| 10 | Live Chain Status & Mempool | Query `GET https://api.prlscan.com/v1/status` for tip height, tip hash, node health | M2 | Survey 2, 3 | DONE |
| 11 | Live Market Price & Exchange Rates | Query `GET https://api.prlscan.com/v1/market/prl` and Kryptex rates for accurate pricing | M2 | Survey 2, 3 | DONE |
| 12 | Live Mining Pool Stats | Connect `https://api.prlscan.com/v1/pools` and HeroMiners pool stats | M2 | Survey 2, 3 | DONE |
| 13 | RPC Settings Modal & Switching | Implement `#sheet-rpc-settings` modal in `index.html` and connect `window.selectRpc` | M2 | Survey 1, 2, 3 | DONE |
| 14 | Network Timeout & Error Feedback | Implement fetch timeouts (`AbortController`) and user-facing error toasts/banners | M2 | Survey 2, 3 | DONE |
| 15 | Service Worker Cache Protection | Exclude external API requests from HTML cache fallback in `sw.js` | M2 | Survey 2 | DONE |
| 16 | Bech32m Address Validation | Implement `decodeBech32m` to validate recipient addresses and prevent invalid transfers | M3 | Survey 3 | DONE |
| 17 | BIP-39 Wordlist & Duplicate Check | Validate imported words against BIP-39 wordlist and prevent duplicate wallet additions | M3 | Survey 3 | DONE |
| 18 | Asset Synchronization | Synchronize root web assets to `dist/` and Capacitor native projects (`android`, `ios`) | M3 | Survey 1 | DONE |
| 19 | E2E Automated Verification Test Suite | Implement comprehensive `node --test` suite covering zero mock data, live RPC/API, and workflows | M4 / E2E Track | Survey 1, 2, 3 | DONE |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| 1 | M1: Clean Mock & Test Data | Features 1-7: Complete removal of all hardcoded mock data, test addresses, fake state mutations, random jitter, and synthetic charts. | none | DONE |
| 2 | M2: Live Public Network & RPC Integration | Features 8-15: Connect live zero-auth `api.prlscan.com` and public pool APIs; add RPC settings modal; implement timeouts and error handling. | M1 | DONE |
| 3 | M3: Wallet Validation & Asset Sync | Features 16-18: Implement Bech32m checksum validation, BIP-39 wordlist verification, and sync web assets to `dist/` & Capacitor. | M2 | DONE |
| 4 | M4: Final Milestone (E2E Test Pass & Hardening) | Feature 19: 100% pass of E2E test suite (Tiers 1-4) followed by Phase 2 adversarial coverage hardening (Tier 5). | M1, M2, M3, TEST_READY | DONE (31/31 tests pass, 100% SHA256 parity, Gate 4 PASS) |

## Interface Contracts

### Public API Gateway Contract (`api.prlscan.com/v1`)
- `GET /v1/status` → `{ tip_height: number, tip_hash: string, node_height: number, mempool_size: number, healthy: boolean }`
- `GET /v1/addresses/{address}` → `{ balance_grains: number, received_grains: number, sent_grains: number, tx_count: number }` (PRL = `balance_grains / 1e8`)
- `GET /v1/addresses/{address}/txs?limit={N}` → `{ items: Array<{ txid: string, time: string, delta_grains: number, fee_grains: number, status: string, type_label?: string }> }`
- `GET /v1/market/prl` → `{ price_usd: number, price_change_24h_pct: number, source: string }`
- `GET /v1/pools` → `{ items: Array<{ name: string, reported_workers: number, estimated_hashrate_hps: number }> }`

### Internal Wallet State Contract (`app.js`)
- `state.contacts`: `Array<{ id: string, name: string, address: string, createdAt: string }>` (empty `[]` on fresh install).
- `state.wallets`: `Array<{ id: string, name: string, pin: string, mnemonic: string[], address: string, privateKeyHex: string, balance: number, createdAt: string }>`
- `fetchAddressBalance(address: string)` → `Promise<number>` (fetches live balance in PRL from `api.prlscan.com`).
- `fetchAddressTransactions(address: string, limit?: number)` → `Promise<Array<TxItem>>` (fetches live tx history).
- `validatePearlAddress(address: string)` → `boolean` (validates `prl1p...` Bech32m witness v1 checksum).

## Code Layout
- Root Web Source:
  - `index.html`: Main wallet UI, views, sheets, navigation, modals.
  - `app.js`: Core wallet controller, state management, crypto, API client.
  - `style.css`: Custom CSS animations, glassmorphism, mobile layout overrides.
  - `bip39-wordlist.js`: BIP-39 English wordlist (2048 words).
  - `qrcode.min.js`: Offline QR code generator.
  - `sw.js`: Service worker caching with API isolation.
  - `manifest.json`: Web application manifest.
- Node Server & Testing:
  - `server.js`: Development web server (`port 3333`).
  - `test/`: Automated test suite executed via `node --test test/*.test.js` or `npm test`.
  - `scripts/`:
    - `scripts/sync-assets.js`: Multi-target asset synchronization runner.
    - `scripts/verify-sync.js`: Multi-target hash parity and mock hygiene verifier.
- Mobile Build Targets:
  - `dist/`: Web distribution bundle (synchronized from root).
  - `android/`: Android Studio Capacitor project (`io.pearl.wallet`).
  - `ios/`: Xcode Capacitor project (`io.pearl.wallet`).
- Team Metadata:
  - `.agents/teamwork/`: Orchestration state, briefing, reports (metadata only).
