0x52

medium

# PerpDepository#_placePerpOrder miscalculates fees paid when shorting

## Summary

PerpDepository#_placePerpOrder calculates the fee as a percentage of the quoteToken received. The issue is that this amount already has the fees taken so the fee percentage is being applied incorrectly.

## Vulnerability Detail

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

    function _calculatePerpOrderFeeAmount(uint256 amount)
        internal
        view
        returns (uint256)
    {
        return amount.mulWadUp(getExchangeFeeWad());
    }

When calculating fees, `PerpDepository#_placePerpOrder` use the quote amount retuned when opening the new position. It always uses exactIn which means that for shorts the amount of baseAsset being sold is specified. The result is that quote amount returned is already less the fees. If we look at how the fee is calculated we can see that it is incorrect.

Example:
Imagine the market price of ETH is $1000 and there is a market fee of 1%. The 1 ETH is sold and the contract receives 990 USD. Using the math above it would calculated the fee as $99 (990 * 1%) but actually the fee is $100.

It have submitted this as a medium because it is not clear from the given contracts what the fee totals are used for and I cannot fully assess the implications of the fee value being incorrect.

## Impact

totalFeesPaid will be inaccurate which could lead to disparities in other contracts depending on how it is used

## Code Snippet

https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/integrations/perp/PerpDepository.sol#L804-L810

## Tool used

Manual Review

## Recommendation

Rewrite _calculatePerpOrderFeeAmount to correctly calculate the fees paid:

    -   function _calculatePerpOrderFeeAmount(uint256 amount)
    +   function _calculatePerpOrderFeeAmount(uint256 amount, bool isShort)
            internal
            view
            returns (uint256)
        {
    +       if (isShort) {
    +           return amount.divWadDown(WAD - getExchangeFeeWad()) - amount;
    +       } else {
                return amount.mulWadUp(getExchangeFeeWad());
    +       }
        }