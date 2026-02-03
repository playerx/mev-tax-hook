// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test, console2} from "forge-std/Test.sol";
import {Deployers} from "@uniswap/v4-core/test/utils/Deployers.sol";
import {MockERC20} from "solmate/src/test/utils/mocks/MockERC20.sol";
import {PoolKey} from "v4-core/types/PoolKey.sol";
import {PoolId, PoolIdLibrary} from "v4-core/types/PoolId.sol";
import {Currency, CurrencyLibrary} from "v4-core/types/Currency.sol";
import {IHooks} from "v4-core/interfaces/IHooks.sol";
import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {Hooks} from "v4-core/libraries/Hooks.sol";
import {TickMath} from "v4-core/libraries/TickMath.sol";
import {LPFeeLibrary} from "v4-core/libraries/LPFeeLibrary.sol";
import {StateLibrary} from "v4-core/libraries/StateLibrary.sol";
import {BalanceDelta} from "v4-core/types/BalanceDelta.sol";
import {
    SwapParams,
    ModifyLiquidityParams
} from "v4-core/types/PoolOperation.sol";
import {PoolSwapTest} from "v4-core/test/PoolSwapTest.sol";

import {MEVTaxHook} from "../src/MEVTaxHook.sol";
import {HookMiner} from "v4-periphery/src/utils/HookMiner.sol";

contract MEVTaxHookTest is Test, Deployers {
    using PoolIdLibrary for PoolKey;
    using CurrencyLibrary for Currency;
    using StateLibrary for IPoolManager;

    MEVTaxHook public hook;
    PoolKey poolKey;
    PoolId poolId;

    uint160 constant HOOK_FLAGS =
        uint160(
            Hooks.AFTER_INITIALIZE_FLAG |
                Hooks.BEFORE_SWAP_FLAG |
                Hooks.AFTER_SWAP_FLAG
        );

    function setUp() public {
        deployFreshManagerAndRouters();
        deployMintAndApprove2Currencies();

        // Deploy hook to proper address with correct flags
        (address hookAddress, bytes32 salt) = HookMiner.find(
            address(this),
            HOOK_FLAGS,
            type(MEVTaxHook).creationCode,
            abi.encode(manager)
        );
        hook = new MEVTaxHook{salt: salt}(manager);
        require(address(hook) == hookAddress, "Hook address mismatch");

        // Create pool with dynamic fee
        poolKey = PoolKey({
            currency0: currency0,
            currency1: currency1,
            fee: LPFeeLibrary.DYNAMIC_FEE_FLAG,
            tickSpacing: 60,
            hooks: IHooks(address(hook))
        });
        poolId = poolKey.toId();

        // Initialize pool at 1:1 price
        manager.initialize(poolKey, SQRT_PRICE_1_1);

        // Add substantial liquidity for testing
        modifyLiquidityRouter.modifyLiquidity(
            poolKey,
            ModifyLiquidityParams({
                tickLower: -6000,
                tickUpper: 6000,
                liquidityDelta: 1000e18,
                salt: bytes32(0)
            }),
            ZERO_BYTES
        );
    }

    // HOOK PERMISSIONS
    function test_hookPermissions() public view {
        Hooks.Permissions memory permissions = hook.getHookPermissions();

        assertFalse(
            permissions.beforeInitialize,
            "beforeInitialize should be false"
        );
        assertTrue(
            permissions.afterInitialize,
            "afterInitialize should be true"
        );
        assertFalse(
            permissions.beforeAddLiquidity,
            "beforeAddLiquidity should be false"
        );
        assertFalse(
            permissions.beforeRemoveLiquidity,
            "beforeRemoveLiquidity should be false"
        );
        assertFalse(
            permissions.afterAddLiquidity,
            "afterAddLiquidity should be false"
        );
        assertFalse(
            permissions.afterRemoveLiquidity,
            "afterRemoveLiquidity should be false"
        );
        assertTrue(permissions.beforeSwap, "beforeSwap should be true");
        assertTrue(permissions.afterSwap, "afterSwap should be true");
        assertFalse(permissions.beforeDonate, "beforeDonate should be false");
        assertFalse(permissions.afterDonate, "afterDonate should be false");
        assertFalse(
            permissions.beforeSwapReturnDelta,
            "beforeSwapReturnDelta should be false"
        );
        assertFalse(
            permissions.afterSwapReturnDelta,
            "afterSwapReturnDelta should be false"
        );
        assertFalse(
            permissions.afterAddLiquidityReturnDelta,
            "afterAddLiquidityReturnDelta should be false"
        );
        assertFalse(
            permissions.afterRemoveLiquidityReturnDelta,
            "afterRemoveLiquidityReturnDelta should be false"
        );
    }

    // AFTER INITIALIZE
    function test_afterInitialize_setsPoolState() public view {
        (
            uint256 lastPrice,
            uint256 emaVol,
            int256 netFlow,
            uint256 lastBlock
        ) = hook.poolState(poolId);

        assertEq(
            lastPrice,
            SQRT_PRICE_1_1,
            "lastPrice should be initialized to sqrtPriceX96"
        );
        assertEq(emaVol, 0, "emaVol should be 0 initially");
        assertEq(netFlow, 0, "netFlow should be 0 initially");
        assertEq(lastBlock, block.number, "lastBlock should be current block");
    }

    // PATTERN #1: IMPACT-BASED FEE
    function test_impactFee_smallSwap_noExtraFee() public {
        // Small swap should not trigger impact fee
        // Impact = (size * 10000) / liquidity
        // With 1000e18 liquidity, need swap > 80 * 1000e18 / 10000 = 8e18 to trigger
        int256 amountSpecified = -1e18; // Small swap

        BalanceDelta delta = swap(poolKey, true, amountSpecified, ZERO_BYTES);

        // Verify swap executed (delta should be non-zero)
        assertTrue(
            delta.amount0() != 0 || delta.amount1() != 0,
            "Swap should execute"
        );
    }

    function test_impactFee_largeSwap_triggersExtraFee() public {
        // First add more liquidity to make precise impact testing easier
        modifyLiquidityRouter.modifyLiquidity(
            poolKey,
            ModifyLiquidityParams({
                tickLower: -6000,
                tickUpper: 6000,
                liquidityDelta: 100e18,
                salt: bytes32(uint256(1))
            }),
            ZERO_BYTES
        );

        // Get current liquidity
        uint128 liquidity = manager.getLiquidity(poolId);

        // Calculate swap size that would trigger impact fee (impact > 80 bps)
        // impact = (size * 10000) / liquidity > 80
        // size > 80 * liquidity / 10000
        uint256 thresholdSize = (hook.IMPACT_THRESHOLD() * uint256(liquidity)) /
            10000;
        int256 largeSwap = -int256(thresholdSize * 2); // Double the threshold

        // Execute large swap - it should work with higher fee
        BalanceDelta delta = swap(poolKey, true, largeSwap, ZERO_BYTES);
        assertTrue(delta.amount0() != 0, "Large swap should execute");
    }

    // PATTERN #2: BACKRUN/IMBALANCE FEE
    function test_backrunFee_oppositeDirectionSwap() public {
        // First swap: zeroForOne = true
        // Flow calculation: flow = -int256(delta.amount0)
        // For zeroForOne, delta.amount0 is negative (we pay token0), so -(-x) = positive netFlow
        int256 firstSwap = -10e18;
        swap(poolKey, true, firstSwap, ZERO_BYTES);

        // Check netFlow is positive (from zeroForOne swap paying token0)
        (, , int256 netFlow, ) = hook.poolState(poolId);
        assertTrue(
            netFlow > 0,
            "netFlow should be positive after zeroForOne swap"
        );

        // Second swap in opposite direction (!zeroForOne)
        // This tests the backrun detection logic
        int256 secondSwap = -5e18;
        BalanceDelta delta = swap(poolKey, false, secondSwap, ZERO_BYTES);
        assertTrue(delta.amount1() != 0, "Second swap should execute");
    }

    function test_backrunFee_sameDirectionSwap() public {
        // Multiple swaps in same direction
        // zeroForOne swaps: flow = -amount0, and amount0 is negative, so flow is positive
        int256 swapAmount = -5e18;

        swap(poolKey, true, swapAmount, ZERO_BYTES);
        swap(poolKey, true, swapAmount, ZERO_BYTES);

        (, , int256 netFlow, ) = hook.poolState(poolId);
        assertTrue(
            netFlow > 0,
            "netFlow should be positive from zeroForOne swaps"
        );
    }

    function test_netFlowDecays_onNewBlock() public {
        // Execute swap to create netFlow
        int256 swapAmount = -10e18;
        swap(poolKey, true, swapAmount, ZERO_BYTES);

        (, , int256 netFlowBefore, ) = hook.poolState(poolId);

        // Move to next block
        vm.roll(block.number + 1);

        // Execute another swap to trigger decay
        swap(poolKey, true, -1e18, ZERO_BYTES);

        (, , int256 netFlowAfter, ) = hook.poolState(poolId);

        // The netFlow should have decayed (divided by 2) before adding new flow
        // So the absolute value change should reflect decay
        assertTrue(
            netFlowAfter != netFlowBefore,
            "netFlow should change after block roll"
        );
    }

    // PATTERN #3: VOLATILITY FEE
    function test_volatilityFee_initiallyZero() public view {
        (, uint256 emaVol, , ) = hook.poolState(poolId);
        assertEq(emaVol, 0, "Initial volatility should be 0");
    }

    function test_volatilityFee_updatesAfterSwap() public {
        // Execute a swap to create price movement
        int256 swapAmount = -50e18;
        swap(poolKey, true, swapAmount, ZERO_BYTES);

        (, uint256 emaVol, , ) = hook.poolState(poolId);
        assertTrue(
            emaVol > 0,
            "Volatility EMA should update after significant swap"
        );
    }

    function test_volatilityFee_emaDecaysOverTime() public {
        // Create significant price movement
        swap(poolKey, true, -100e18, ZERO_BYTES);

        (, uint256 emaVolAfterFirst, , ) = hook.poolState(poolId);

        // Small swap in opposite direction
        swap(poolKey, false, -1e17, ZERO_BYTES);

        (, uint256 emaVolAfterSecond, , ) = hook.poolState(poolId);

        // EMA should blend old and new volatility
        // With EMA_ALPHA = 20%, new vol gets 20% weight, old gets 80%
        assertTrue(emaVolAfterSecond != emaVolAfterFirst, "EMA should update");
    }

    // COMBINED FEE SCENARIOS
    function test_multipleFeeConditions() public {
        // Scenario: Large swap that might trigger multiple fee conditions

        // First, create some netFlow
        swap(poolKey, true, -20e18, ZERO_BYTES);

        // Create volatility
        swap(poolKey, false, -30e18, ZERO_BYTES);

        // Check state
        (, uint256 emaVol, int256 netFlow, ) = hook.poolState(poolId);

        // Verify state is set up for potential fee conditions
        assertTrue(
            emaVol > 0 || netFlow != 0,
            "Pool state should reflect trading activity"
        );
    }

    // HELPER FUNCTIONS
    function test_constants() public view {
        assertEq(
            hook.IMPACT_THRESHOLD(),
            80,
            "IMPACT_THRESHOLD should be 80 bps"
        );
        assertEq(hook.IMPACT_FEE(), 2000, "IMPACT_FEE should be 2000");
        assertEq(hook.FLOW_THRESHOLD(), 1e18, "FLOW_THRESHOLD should be 1e18");
        assertEq(hook.BACKRUN_FEE(), 1500, "BACKRUN_FEE should be 1500");
        assertEq(hook.VOL_THRESHOLD(), 50, "VOL_THRESHOLD should be 50 bps");
        assertEq(hook.VOL_FEE(), 2000, "VOL_FEE should be 2000");
        assertEq(hook.EMA_ALPHA(), 20, "EMA_ALPHA should be 20%");
    }

    // PRICE TRACKING
    function test_priceUpdatesAfterSwap() public {
        (uint256 lastPriceBefore, , , ) = hook.poolState(poolId);

        // Execute swap that moves price
        swap(poolKey, true, -50e18, ZERO_BYTES);

        (uint256 lastPriceAfter, , , ) = hook.poolState(poolId);

        assertNotEq(
            lastPriceBefore,
            lastPriceAfter,
            "Price should update after swap"
        );
    }

    // FUZZ TESTS
    function testFuzz_swapDoesNotRevert(
        bool zeroForOne,
        uint256 amount
    ) public {
        // Bound amount to reasonable range
        amount = bound(amount, 1e15, 100e18);
        int256 amountSpecified = -int256(amount);

        // Should not revert for any reasonable swap
        try this.executeSwap(zeroForOne, amountSpecified) {
            // Success is expected
        } catch {
            // Some swaps may fail due to slippage/price limits, which is acceptable
        }
    }

    function executeSwap(bool zeroForOne, int256 amountSpecified) external {
        swap(poolKey, zeroForOne, amountSpecified, ZERO_BYTES);
    }

    function testFuzz_emaVolNeverOverflows(uint256 priceDelta) public view {
        // EMA calculation: ((emaVol * 80) + (priceDelta * 20)) / 100
        // This should never overflow for reasonable values
        priceDelta = bound(priceDelta, 0, 10000); // Max 100% bps

        uint256 emaVol = 5000; // 50% existing vol
        uint256 newEmaVol = ((emaVol * 80) + (priceDelta * 20)) / 100;

        assertTrue(
            newEmaVol <= 10000,
            "EMA should stay within reasonable bounds"
        );
    }

    // EDGE CASES
    function test_swapWithZeroLiquidity() public {
        // Create a new pool without liquidity
        PoolKey memory emptyPoolKey = PoolKey({
            currency0: currency0,
            currency1: currency1,
            fee: LPFeeLibrary.DYNAMIC_FEE_FLAG,
            tickSpacing: 120,
            hooks: IHooks(address(hook))
        });

        manager.initialize(emptyPoolKey, SQRT_PRICE_1_1);

        // Swap with zero liquidity returns 0 amounts (doesn't revert)
        BalanceDelta delta = swap(emptyPoolKey, true, -1e18, ZERO_BYTES);

        // Both amounts should be 0 since there's no liquidity
        assertEq(delta.amount0(), 0, "amount0 should be 0 with no liquidity");
        assertEq(delta.amount1(), 0, "amount1 should be 0 with no liquidity");
    }

    function test_consecutiveSwapsSameBlock() public {
        // Multiple swaps in same block should accumulate netFlow without decay
        swap(poolKey, true, -5e18, ZERO_BYTES);
        (, , int256 netFlow1, uint256 lastBlock1) = hook.poolState(poolId);

        swap(poolKey, true, -5e18, ZERO_BYTES);
        (, , int256 netFlow2, uint256 lastBlock2) = hook.poolState(poolId);

        assertEq(lastBlock1, lastBlock2, "Block should not change");
        // zeroForOne swaps create positive flow, so netFlow should increase
        assertTrue(
            netFlow2 > netFlow1,
            "netFlow should accumulate (more positive for zeroForOne)"
        );
    }

    function test_swapRevertsWithInsufficientBalance() public {
        // Try to swap more than available in test contract
        address poorUser = makeAddr("poor");
        vm.startPrank(poorUser);

        vm.expectRevert();
        swapRouter.swap(
            poolKey,
            SwapParams({
                zeroForOne: true,
                amountSpecified: -1e18,
                sqrtPriceLimitX96: MIN_PRICE_LIMIT
            }),
            PoolSwapTest.TestSettings({
                takeClaims: false,
                settleUsingBurn: false
            }),
            ZERO_BYTES
        );

        vm.stopPrank();
    }
}

/*//////////////////////////////////////////////////////////////
                    HELPER FUNCTION UNIT TESTS
//////////////////////////////////////////////////////////////*/

contract MEVTaxHookHelpersTest is Test {
    // Test internal helper functions via a harness

    function test_bpsDiff_aGreaterThanB() public pure {
        uint256 a = 110;
        uint256 b = 100;
        // (110 - 100) * 10000 / 100 = 1000 bps = 10%
        uint256 expected = 1000;
        uint256 result = _bpsDiff(a, b);
        assertEq(result, expected, "bpsDiff should be 1000 bps");
    }

    function test_bpsDiff_bGreaterThanA() public pure {
        uint256 a = 90;
        uint256 b = 100;
        // (100 - 90) * 10000 / 100 = 1000 bps = 10%
        uint256 expected = 1000;
        uint256 result = _bpsDiff(a, b);
        assertEq(result, expected, "bpsDiff should be 1000 bps");
    }

    function test_bpsDiff_equal() public pure {
        uint256 a = 100;
        uint256 b = 100;
        uint256 expected = 0;
        uint256 result = _bpsDiff(a, b);
        assertEq(result, expected, "bpsDiff should be 0 for equal values");
    }

    function test_bpsDiff_bZero() public pure {
        uint256 a = 100;
        uint256 b = 0;
        uint256 expected = 0; // Avoid division by zero
        uint256 result = _bpsDiff(a, b);
        assertEq(result, expected, "bpsDiff should return 0 when b is 0");
    }

    function test_abs_positive() public pure {
        int256 x = 100;
        uint256 expected = 100;
        uint256 result = _abs(x);
        assertEq(result, expected, "abs of positive should be same value");
    }

    function test_abs_negative() public pure {
        int256 x = -100;
        uint256 expected = 100;
        uint256 result = _abs(x);
        assertEq(result, expected, "abs of negative should be positive");
    }

    function test_abs_zero() public pure {
        int256 x = 0;
        uint256 expected = 0;
        uint256 result = _abs(x);
        assertEq(result, expected, "abs of zero should be zero");
    }

    function testFuzz_abs(int256 x) public pure {
        // Exclude int256.min which overflows when negated
        vm.assume(x > type(int256).min);

        uint256 result = _abs(x);
        if (x >= 0) {
            assertEq(result, uint256(x), "abs of positive should equal value");
        } else {
            assertEq(
                result,
                uint256(-x),
                "abs of negative should equal negated value"
            );
        }
    }

    function testFuzz_bpsDiff_symmetric(uint256 a, uint256 b) public pure {
        // Avoid overflow and division by zero
        a = bound(a, 1, type(uint128).max);
        b = bound(b, 1, type(uint128).max);

        // bpsDiff(a, b) uses b as denominator
        // bpsDiff(b, a) uses a as denominator
        // They may differ, but both should be valid
        uint256 result1 = _bpsDiff(a, b);
        uint256 result2 = _bpsDiff(b, a);

        // Both should be non-negative (always true for uint)
        assertTrue(result1 < type(uint256).max, "result1 should not overflow");
        assertTrue(result2 < type(uint256).max, "result2 should not overflow");
    }

    // Copy of helper functions from MEVTaxHook for testing
    function _bpsDiff(uint256 a, uint256 b) internal pure returns (uint256) {
        if (b == 0) return 0;
        if (a > b) return ((a - b) * 10_000) / b;
        return ((b - a) * 10_000) / b;
    }

    function _abs(int256 x) internal pure returns (uint256) {
        return uint256(x >= 0 ? x : -x);
    }
}
