# Test Infrastructure & Test Suite Specification: pearl-walle

## 1. Overview & Architecture

The `pearl-walle` test suite is designed as an **automated, opaque-box, requirement-driven verification system** built exclusively using Node.js's native test runner (`node:test`) and strict assertion module (`node:assert/strict`).

### Key Design Principles:
1. **Zero External Dependencies**: Operates strictly on Node.js built-ins (`node:test`, `node:assert/strict`, `fetch`, `node:fs`, `node:path`, `node:vm`, `crypto`). No third-party npm test packages required.
2. **Opaque-Box & Requirement-Driven**: Tests are derived directly from `ORIGINAL_REQUEST.md` and `PROJECT.md` specifications rather than internal implementation quirks.
3. **Four-Tier Verification Structure**: Stratified test tiers ranging from unit/feature coverage to adversarial boundary cases, cross-feature flows, and live on-chain mainnet validation.
4. **Authoritative Mathematical & Network Oracles**: Includes native BIP-350/BIP-341 Bech32m polymod checksum verification (`0x2bc830a3`), BIP-39 dictionary verification, static code scanning, and live queries against `https://api.prlscan.com/v1`, Kryptex, and HeroMiners APIs.

---

## 2. Directory Layout

```
test/
├── helpers/
│   ├── bech32m.js          # BIP-350 Bech32m encoder/decoder & Pearl address validation oracle
│   ├── bip39.js            # BIP-39 2048-word dictionary loader & mnemonic phrase validator
│   ├── scanner.js          # Static codebase scanner for mock data, test addresses, and fake state mutations
│   ├── api-client.js       # Live zero-auth API client for prlscan, Kryptex, and HeroMiners
│   └── runtime-sandbox.js  # Sandboxed in-memory localStorage and DOM environment for clean boot testing
├── tier1-feature-coverage.test.js  # Tier 1: Feature Coverage (5 tests)
├── tier2-boundary-corner.test.js   # Tier 2: Boundary & Corner Cases (7 tests)
├── tier3-cross-feature.test.js     # Tier 3: Cross-Feature Combinations (3 tests)
└── tier4-real-world.test.js        # Tier 4: Real-World Application Scenarios (3 tests)
```

---

## 3. Test Tier Inventory

### Tier 1: Feature Coverage (`test/tier1-feature-coverage.test.js`)
Validates fundamental feature requirements and baseline guarantees:
- **T1.1**: Static scan verifies zero mock mnemonics (`lottery girl rain...`), test miner buttons/functions (`fillTestMinerAddress`), auto-saved mock contacts (`contact-default-1/2`), and fake send state balance mutations.
- **T1.2**: Fresh launch verification ensuring application initializes with pristine storage (`pearl_contacts_v1` is null/empty, `pearl_wallets_v1` is null/empty).
- **T1.3**: Live public RPC gateway (`https://api.prlscan.com/v1/status`) connectivity, verifying healthy mainnet status, tip height > 130,000, and 64-char block hash.
- **T1.4**: Real address balance inquiry on active miner address (`prl1pvxtfv9c7a9elgny7jmhndtl9cwdy9wnhvphg7g5arxjvc2rwa4vq09sfpm`), verifying genuine `balance_grains` and `tx_count > 0`.
- **T1.5**: Wallet creation logic producing standard 12-word BIP-39 mnemonic and valid Taproot Bech32m witness v1 address (`prl1p...`, 63 chars).

### Tier 2: Boundary & Corner Cases (`test/tier2-boundary-corner.test.js`)
Stresses boundary limits, invalid inputs, and error handling:
- **T2.1**: Empty string and whitespace-only mnemonic input rejection.
- **T2.2**: Invalid mnemonic word counts (0, 1, 5, 11, 13, 23, 25 words) rejection.
- **T2.3**: Non-BIP-39 dictionary words, digits, and special characters rejection.
- **T2.4**: Malformed address HRP (`bc1`, `eth1`), invalid separator, and invalid witness version (`prl1q`) rejection.
- **T2.5**: Malformed address charset (`b`, `i`, `o`, `1` in payload), mixed case, corrupted checksum characters, and extreme lengths (<8 or >90) rejection.
- **T2.6**: Negative, zero, NaN, non-numeric, Infinity, and sub-fee transfer amount rejection in transfer validator.
- **T2.7**: Network timeout handling with `AbortController` and clean error propagation without unhandled rejection.

### Tier 3: Cross-Feature Combinations (`test/tier3-cross-feature.test.js`)
Validates multi-module interactions and state integrity:
- **T3.1**: Wallet creation -> Bech32m validation -> live on-chain query for fresh address (verifies 0 balance and 0 tx count).
- **T3.2**: Known address import -> Bech32m verification -> live balance query -> live transaction history query with confirmed txids and timestamps.
- **T3.3**: Multi-wallet state management, ensuring duplicate address import is prevented and active wallet switching preserves isolated balances.

### Tier 4: Real-World Application Scenarios (`test/tier4-real-world.test.js`)
Validates complete user journeys and real external service consensus:
- **T4.1**: Fresh user onboarding end-to-end lifecycle (clean storage -> 12-word BIP-39 generation -> Bech32m address derivation -> wallet persistence -> clean address book).
- **T4.2**: Real on-chain miner address query and cross-provider height consensus (Explorer `tip_height` vs HeroMiners `networkHeight` within 25 blocks).
- **T4.3**: Real market price feeds from CoinMarketCap (`/v1/market/prl`) and Kryptex (`/api/v1/rates`) verifying positive prices and absence of synthetic client-side `Math.random()` jitter.

---

## 4. Execution Commands

### Execute Entire Test Suite (All 18 Tests)
```bash
node --test test/*.test.js
```

### Execute by Tier
```bash
# Tier 1: Feature Coverage
node --test test/tier1-feature-coverage.test.js

# Tier 2: Boundary & Corner Cases
node --test test/tier2-boundary-corner.test.js

# Tier 3: Cross-Feature Combinations
node --test test/tier3-cross-feature.test.js

# Tier 4: Real-World Application Scenarios
node --test test/tier4-real-world.test.js
```

---

## 5. Environment & System Requirements

- **Runtime**: Node.js v18.0.0+ (Tested and verified on Node.js v24.14.0).
- **Network**: Internet access required for live public blockchain probes (`api.prlscan.com`, `pool.kryptex.com`, `pearl.herominers.com`).
- **Dependencies**: None.
