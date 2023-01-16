DecorativePineapple

medium

# No slippage protection when opening short or long position

## Summary
When opening a long/short position, the [`_placePerpOrder`](https://github.com/sherlock-audit/2023-01-uxd/blob/2f3e8890ba64331be08b690018f93d3b67e82c11/contracts/integrations/perp/PerpDepository.sol#L346) function is called which calls the `openPosition` function on the `ClearingHouse` contract. However, both the `sqrtPriceLimitX96` and the `oppositeAmountBound` parameters are set to 0 on the `OpenPositionParams` struct, which disables the slippage protection.

## Vulnerability Detail
On the [Perpetual Protocol Docs](https://support.perp.com/hc/en-us/articles/5257495077145-Opening-and-Closing-Positions) it's mentioned that when a Long Position is opened you are trading quote tokens (e.g. USD) for base tokens (e.g. ETH, BTC, etc.) and when a short position is opened you are trading base tokens (e.g. ETH, BTC, etc.) for quote tokens (e.g. USD). For this reason the `OpenPositionParams` struct which is given as the argument to  `openPosition` function of the `ClearingHouse` smart contract introduced 2 parameters for slippage protection: `sqrtPriceLimitX96` and `oppositeAmountBound`. However the `openPosition` function is called without a slippage protection; both the `sqrtPriceLimitX96` and `oppositeAmountBound` parameters are set to 0. An attacker can monitor the mempool for the trade and effectively sandwich the trade in order to get a profit.

## Impact
No slippage protection - an attacker can sandwich the trade of quote tokens (e.g. USD) for base tokens (e.g. ETH, BTC, etc.) , if it's a long position or the trade of  base tokens (e.g. ETH, BTC, etc.) for quote tokens (e.g. USD) if it's a short position for profit. 

## Code Snippet
The `_openLong`, `_openShort` and [`_placePerpOrder`](https://github.com/sherlock-audit/2023-01-uxd/blob/2f3e8890ba64331be08b690018f93d3b67e82c11/contracts/integrations/perp/PerpDepository.sol#L346) functions:
```solidity
 /// @notice Opens a long position on the perpetual DEX.
    /// @dev This closes a portion of the previously open short backing the delta-neutral position.
    /// Only called by the controller
    /// @param amount The amount to open long position for.
    /// `isBaseToQuote == false`, `exactInput == true`, so this is the quote amount.
    function _openLong(uint256 amount)
        private
        returns (uint256, uint256)
    {
        (uint256 baseAmount, uint256 quoteAmount) = _placePerpOrder(
            amount,
            false, // isShort
            true, // isExactInput
            0 // sqrtPriceLimitX96
        );
        redeemableUnderManagement -= quoteAmount;

        return (baseAmount, quoteAmount);
    }
 /// @notice Opens a short position on the perpetual DEX.
    /// @dev This increases the size of the delta-neutral position.
    /// Can only be called by the controller
    /// @param amount The amount of short position to open. THis is opened with `exactInput = true`,
    /// thus, this is the input/base token amount.
    /// @return base, quote
    function _openShort(uint256 amount)
        private
        returns (uint256, uint256)
    {
        (uint256 baseAmount, uint256 quoteAmount) = _placePerpOrder(
            amount,
            true, // short
            true, // exactInput
            0
        );
        redeemableUnderManagement += quoteAmount;
        _checkSoftCap();
        // emit event here
        return (baseAmount, quoteAmount);
    }

    function _placePerpOrder(
        uint256 amount,
        bool isShort,
        bool amountIsInput,
        uint160 sqrtPriceLimit
    ) private returns (uint256, uint256) {
        uint256 upperBound = 0; // 0 = no limit, limit set by sqrtPriceLimit

        IClearingHouse.OpenPositionParams memory params = IClearingHouse
            .OpenPositionParams({
                baseToken: market,
                isBaseToQuote: isShort, // true for short
                isExactInput: amountIsInput, // we specify exact input amount
                amount: amount, // collateral amount - fees
                oppositeAmountBound: upperBound, // output upper bound
                // solhint-disable-next-line not-rely-on-time
                deadline: block.timestamp,
                sqrtPriceLimitX96: sqrtPriceLimit, // max slippage
                referralCode: 0x0
            });

        (uint256 baseAmount, uint256 quoteAmount) = clearingHouse.openPosition(
            params
        );
        uint256 feeAmount = _calculatePerpOrderFeeAmount(quoteAmount);
        totalFeesPaid += feeAmount;

        emit PositionOpened(isShort, amount, amountIsInput, sqrtPriceLimit);
        return (baseAmount, quoteAmount);
    }
```

## Tool used
Manual Review

## Recommendation
It is advised to either let the user decide the `oppositeAmountBound` or the `sqrtPriceLimitX96` parameters when opening a long/short position. Also a router or a price oracle can be utilized that fetches the trade prices of assets and set them as the `sqrtPriceLimitX96` parameter.
