berndartmueller

high

# Rebalancing a negative Perp PnL via a Uniswap V3 token swap is broken due to the lack of token spending allowance

## Summary

The `ISwapper spotSwapper` (i.e., `Uniswapper`) helper contract, used by the `PerpDepository._rebalanceNegativePnlWithSwap` function to perform the actual Uniswap V3 token swap, is missing the required `assetToken` spending allowance due to a lack of calling the `assetToken.approve` function.

## Vulnerability Detail

Rebalancing a negative Perp PnL with the `PerpDepository.rebalance` function calls the `_rebalanceNegativePnlWithSwap` function, which performs a Uniswap swap. However, the required `assetToken` spending allowance for the `ISwapper spotSwapper` (i.e. `Uniswapper`) helper contract is missing. This leads to a revert due to insufficient allowance.

## Impact

Rebalancing a negative Perp PnL via a Uniswap swap is missing the token approval and leads to a revert.

## Code Snippet

[integrations/perp/PerpDepository.sol#L507](https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/integrations/perp/PerpDepository.sol#L507)

```solidity
function _rebalanceNegativePnlWithSwap(
    uint256 amount,
    uint256 amountOutMinimum,
    uint160 sqrtPriceLimitX96,
    uint24 swapPoolFee,
    address account
) private returns (uint256, uint256) {
    uint256 normalizedAmount = amount.fromDecimalToDecimal(
        ERC20(quoteToken).decimals(),
        18
    );
    _checkNegativePnl(normalizedAmount);
    bool isShort = false;
    bool amountIsInput = true;
    (uint256 baseAmount, uint256 quoteAmount) = _placePerpOrder(
        normalizedAmount,
        isShort,
        amountIsInput,
        sqrtPriceLimitX96
    );
    vault.withdraw(assetToken, baseAmount);
    SwapParams memory params = SwapParams({
        tokenIn: assetToken,
        tokenOut: quoteToken,
        amountIn: baseAmount,
        amountOutMinimum: amountOutMinimum,
        sqrtPriceLimitX96: sqrtPriceLimitX96,
        poolFee: swapPoolFee
    });
    uint256 quoteAmountOut = spotSwapper.swapExactInput(params); // @audit-info missing token approval

    // [...]
}
```

## Tool used

Manual Review

## Recommendation

Consider adding the appropriate token approval before the swap in L507.
