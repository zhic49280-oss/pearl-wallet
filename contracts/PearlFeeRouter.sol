// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 value) external returns (bool);
    function transferFrom(address from, address to, uint256 value) external returns (bool);
    function approve(address spender, uint256 value) external returns (bool);
}

/**
 * @title PearlFeeRouter
 * @notice Non-custodial EVM swap fee router (Scheme B).
 *         Collects a capped platform fee (default 25 bps = 0.25%) and forwards
 *         the net input to an allowlisted DEX / aggregator router in a single atomic tx.
 */
contract PearlFeeRouter {
    uint256 public constant MAX_FEE_BPS = 200; // 2.00% hard cap
    uint256 public constant BPS_DENOMINATOR = 10_000;

    address public owner;
    address public feeReceiver;
    uint256 public feeBps;
    mapping(address => bool) public approvedRouters;

    uint256 private _locked = 1;

    event SwapWithFee(
        address indexed user,
        address indexed router,
        address indexed tokenIn,
        uint256 grossAmountIn,
        uint256 feeAmount
    );
    event FeeConfigUpdated(address indexed feeReceiver, uint256 feeBps);
    event RouterApproved(address indexed router, bool approved);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    modifier onlyOwner() {
        require(msg.sender == owner, "ONLY_OWNER");
        _;
    }

    modifier nonReentrant() {
        require(_locked == 1, "REENTRANCY");
        _locked = 2;
        _;
        _locked = 1;
    }

    constructor(address _feeReceiver, uint256 _feeBps, address[] memory _initialRouters) {
        require(_feeReceiver != address(0), "ZERO_RECEIVER");
        require(_feeBps <= MAX_FEE_BPS, "FEE_TOO_HIGH");
        owner = msg.sender;
        feeReceiver = _feeReceiver;
        feeBps = _feeBps;
        for (uint256 i = 0; i < _initialRouters.length; i++) {
            approvedRouters[_initialRouters[i]] = true;
            emit RouterApproved(_initialRouters[i], true);
        }
        emit FeeConfigUpdated(_feeReceiver, _feeBps);
    }

    receive() external payable {}

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "ZERO_OWNER");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    function setFeeConfig(address _feeReceiver, uint256 _feeBps) external onlyOwner {
        require(_feeReceiver != address(0), "ZERO_RECEIVER");
        require(_feeBps <= MAX_FEE_BPS, "FEE_TOO_HIGH");
        feeReceiver = _feeReceiver;
        feeBps = _feeBps;
        emit FeeConfigUpdated(_feeReceiver, _feeBps);
    }

    function setApprovedRouter(address router, bool approved) external onlyOwner {
        require(router != address(0), "ZERO_ROUTER");
        approvedRouters[router] = approved;
        emit RouterApproved(router, approved);
    }

    /**
     * @notice Native ETH/BNB swap with atomic platform fee deduction.
     * @dev Calldata sent to `router` must already be quoted for `msg.value - feeAmount`.
     */
    function swapWithFeeETH(
        address router,
        bytes calldata swapData
    ) external payable nonReentrant {
        require(approvedRouters[router], "ROUTER_NOT_APPROVED");
        require(msg.value > 0, "ZERO_VALUE");

        uint256 feeAmount = (msg.value * feeBps) / BPS_DENOMINATOR;
        uint256 netValue = msg.value - feeAmount;

        if (feeAmount > 0) {
            (bool feeOk, ) = payable(feeReceiver).call{value: feeAmount}("");
            require(feeOk, "FEE_TRANSFER_FAILED");
        }

        (bool ok, bytes memory ret) = router.call{value: netValue}(swapData);
        if (!ok) {
            assembly {
                revert(add(ret, 32), mload(ret))
            }
        }

        emit SwapWithFee(msg.sender, router, address(0), msg.value, feeAmount);
    }

    /**
     * @notice ERC-20 swap with atomic platform fee deduction.
     * @dev Calldata sent to `router` must already be quoted for `amountIn - feeAmount`.
     */
    function swapWithFeeToken(
        address tokenIn,
        uint256 amountIn,
        address router,
        bytes calldata swapData
    ) external nonReentrant {
        require(approvedRouters[router], "ROUTER_NOT_APPROVED");
        require(tokenIn != address(0) && amountIn > 0, "INVALID_INPUT");

        require(IERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn), "PULL_FAILED");

        uint256 feeAmount = (amountIn * feeBps) / BPS_DENOMINATOR;
        uint256 netAmount = amountIn - feeAmount;

        if (feeAmount > 0) {
            require(IERC20(tokenIn).transfer(feeReceiver, feeAmount), "FEE_TRANSFER_FAILED");
        }

        require(IERC20(tokenIn).approve(router, 0), "RESET_APPROVE_FAILED");
        require(IERC20(tokenIn).approve(router, netAmount), "APPROVE_FAILED");

        (bool ok, bytes memory ret) = router.call(swapData);
        if (!ok) {
            assembly {
                revert(add(ret, 32), mload(ret))
            }
        }

        require(IERC20(tokenIn).approve(router, 0), "CLEAR_APPROVE_FAILED");
        emit SwapWithFee(msg.sender, router, tokenIn, amountIn, feeAmount);
    }

    function rescueETH(address to) external onlyOwner {
        require(to != address(0), "ZERO_TO");
        (bool ok, ) = payable(to).call{value: address(this).balance}("");
        require(ok, "RESCUE_FAILED");
    }

    function rescueToken(address token, address to) external onlyOwner {
        require(to != address(0), "ZERO_TO");
        uint256 bal = IERC20(token).balanceOf(address(this));
        require(IERC20(token).transfer(to, bal), "RESCUE_FAILED");
    }
}
