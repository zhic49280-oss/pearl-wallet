# PearlFeeRouter (方案 B：自部署中转收费合约)

## 1. 合约功能
- `PearlFeeRouter.sol` 是一个非托管中转路由合约，默认收款地址为 `0x00dCBFDe63933Dc710Dd804dE58602d267BCCE34`，默认费率 `25 bps`（`0.25%`，硬顶上限 `2%`）。
- 支持 `swapWithFeeETH`（原生币）与 `swapWithFeeToken`（ERC-20），单笔交易原子完成扣费 + 转发给白名单聚合器/DEX Router。

## 2. 部署步骤（EVM 5 条链：`eth` / `base` / `bsc` / `arb` / `hood`）
1. 使用 Remix / Foundry / `solc` 编译 `contracts/PearlFeeRouter.sol`，将 `{ "abi": [...], "bytecode": "0x..." }` 保存到 `contracts/PearlFeeRouter.artifact.json`。
2. 准备一个在对应链上有少量原生 Gas 的部署私钥，执行：
   ```powershell
   $env:DEPLOYER_PRIVATE_KEY="0x你的部署私钥"
   node contracts/deploy-router.js base
   node contracts/deploy-router.js eth
   node contracts/deploy-router.js bsc
   node contracts/deploy-router.js arb
   node contracts/deploy-router.js hood
   ```
3. 把 5 条链返回的合约地址配置进 `app.js` 即可从方案 A 平滑切换至自有合约方案 B。
