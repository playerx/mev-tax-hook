// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import { BaseHook } from "v4-periphery/src/utils/BaseHook.sol";
import { PoolKey } from "v4-core/types/PoolKey.sol";
import { PoolIdLibrary, PoolId } from "v4-core/types/PoolId.sol";
import { IPoolManager } from "v4-core/interfaces/IPoolManager.sol";
import { Hooks } from "v4-core/libraries/Hooks.sol";
import { SwapParams } from "v4-core/types/PoolOperation.sol";
import { BeforeSwapDelta, toBeforeSwapDelta } from "v4-core/types/BeforeSwapDelta.sol";
import { BalanceDelta, BalanceDeltaLibrary } from "v4-core/types/BalanceDelta.sol";
import { StateLibrary } from "v4-core/libraries/StateLibrary.sol";

contract MEVTaxHook is BaseHook {
    using PoolIdLibrary for PoolKey;
    using StateLibrary for IPoolManager;

    /* -------------------- State -------------------- */
    struct PoolState {
        uint256 lastPrice; // sqrtPriceX96
        uint256 emaVol; // volatility EMA (bps)
        int256 netFlow; // signed directional flow
        uint256 lastBlock;
    }

    mapping(PoolId => PoolState) public poolState;

    /* -------------------- Parameters -------------------- */
    // uint24 public constant BASE_FEE = 3000; // 0.30%

    // Pattern #1: impact
    uint256 public constant IMPACT_THRESHOLD = 80; // 0.80%
    uint24 public constant IMPACT_FEE = 2000; // +0.20%

    // Pattern #2: backrun
    int256 public constant FLOW_THRESHOLD = 1e18;
    uint24 public constant BACKRUN_FEE = 1500; // +0.15%

    // Pattern #3: volatility
    uint256 public constant VOL_THRESHOLD = 50; // 0.50%
    uint24 public constant VOL_FEE = 2000; // +0.20%

    uint256 public constant EMA_ALPHA = 20; // %

    /* -------------------- Constructor -------------------- */
    constructor(IPoolManager _manager) BaseHook(_manager) { }

    /* -------------------- Permissions -------------------- */
    function getHookPermissions() public pure override returns (Hooks.Permissions memory) {
        return Hooks.Permissions({
            beforeInitialize: false,
            afterInitialize: true,
            beforeAddLiquidity: false,
            beforeRemoveLiquidity: false,
            afterAddLiquidity: false,
            afterRemoveLiquidity: false,
            beforeSwap: true,
            afterSwap: true,
            beforeDonate: false,
            afterDonate: false,
            beforeSwapReturnDelta: false,
            afterSwapReturnDelta: false,
            afterAddLiquidityReturnDelta: false,
            afterRemoveLiquidityReturnDelta: false
        });
    }

    /* -------------------- Initialize -------------------- */
    function _afterInitialize(address, PoolKey calldata key, uint160 sqrtPriceX96, int24)
        internal
        override
        returns (bytes4)
    {
        PoolId id = key.toId();

        poolState[id] = PoolState({ lastPrice: sqrtPriceX96, emaVol: 0, netFlow: 0, lastBlock: block.number });

        return this.afterInitialize.selector;
    }

    /* -------------------- Before Swap -------------------- */
    function _beforeSwap(address, PoolKey calldata key, SwapParams calldata params, bytes calldata)
        internal
        view
        override
        returns (bytes4, BeforeSwapDelta, uint24)
    {
        PoolState storage s = poolState[key.toId()];
        uint24 fee = key.fee;

        // Pattern #1 — impact-based fee
        uint128 liquidity = poolManager.getLiquidity(key.toId());
        uint256 impact = _estimateImpact(params, liquidity);
        if (impact > IMPACT_THRESHOLD) {
            fee += IMPACT_FEE;
        }

        // Pattern #2 — backrun / imbalance fee
        // zeroForOne swaps produce negative flow, !zeroForOne produce positive flow
        bool sameDirection =
            (params.zeroForOne && s.netFlow < -FLOW_THRESHOLD) || (!params.zeroForOne && s.netFlow > FLOW_THRESHOLD);

        // forge-lint: disable-next-line(unsafe-typecast)
        if (!sameDirection && _abs(s.netFlow) > uint256(FLOW_THRESHOLD)) {
            fee += BACKRUN_FEE;
        }

        // Pattern #3 — volatility / priority flow
        if (s.emaVol > VOL_THRESHOLD) {
            fee += VOL_FEE;
        }

        return (this.beforeSwap.selector, toBeforeSwapDelta(0, 0), fee);
    }

    /* -------------------- After Swap -------------------- */
    function _afterSwap(address, PoolKey calldata key, SwapParams calldata params, BalanceDelta delta, bytes calldata)
        internal
        override
        returns (bytes4, int128)
    {
        PoolState storage s = poolState[key.toId()];

        (uint160 sqrtPriceX96,,,) = poolManager.getSlot0(key.toId());
        uint256 priceAfter = uint256(sqrtPriceX96);

        // Update volatility EMA
        uint256 priceDelta = _bpsDiff(priceAfter, s.lastPrice);
        s.emaVol = ((s.emaVol * (100 - EMA_ALPHA)) + (priceDelta * EMA_ALPHA)) / 100;

        // Decay flow per block (before adding new flow)
        if (s.lastBlock != block.number) {
            s.netFlow /= 2;
            s.lastBlock = block.number;
        }

        // Update directional flow
        int256 flow = params.zeroForOne
            ? -int256(BalanceDeltaLibrary.amount0(delta))
            : int256(BalanceDeltaLibrary.amount1(delta));

        s.netFlow += flow;

        s.lastPrice = priceAfter;

        return (this.afterSwap.selector, 0);
    }

    /* -------------------- Helpers -------------------- */
    function _bpsDiff(uint256 a, uint256 b) internal pure returns (uint256) {
        if (b == 0) return 0; // Avoid division by zero
        if (a > b) return ((a - b) * 10_000) / b;
        return ((b - a) * 10_000) / b;
    }

    function _abs(int256 x) internal pure returns (uint256) {
        return uint256(x >= 0 ? x : -x);
    }

    function _estimateImpact(SwapParams calldata params, uint128 liquidity) internal pure returns (uint256) {
        if (liquidity == 0) return 0;

        uint256 size = uint256(params.amountSpecified > 0 ? params.amountSpecified : -params.amountSpecified);
        return (size * 10_000) / uint256(liquidity);
    }
}
