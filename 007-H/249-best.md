0x52

high

# PerpDepository#getPositionValue uses incorrect value for TWAP interval allowing more than intended funds to be extracted

## Summary

PerpDepository#getPositionValue queries the exchange for the mark price to calculate the unrealized PNL. Mark price is defined as the 15 minute TWAP of the market. The issue is that it uses the 15 second TWAP instead of the 15 minute TWAP

## Vulnerability Detail

As stated in the [docs](https://support.perp.com/hc/en-us/articles/5331299807513-Liquidation) and as implemented in the [ClearHouseConfig](https://optimistic.etherscan.io/address/0xa4c817a425d3443baf610ca614c8b11688a288fb#readProxyContract) contract, the mark price is a 15 minute / 900 second TWAP.

    function getPositionValue() public view returns (uint256) {
        uint256 markPrice = getMarkPriceTwap(15);
        int256 positionSize = IAccountBalance(clearingHouse.getAccountBalance())
            .getTakerPositionSize(address(this), market);
        return markPrice.mulWadUp(_abs(positionSize));
    }

    function getMarkPriceTwap(uint32 twapInterval)
        public
        view
        returns (uint256)
    {
        IExchange exchange = IExchange(clearingHouse.getExchange());
        uint256 markPrice = exchange
            .getSqrtMarkTwapX96(market, twapInterval)
            .formatSqrtPriceX96ToPriceX96()
            .formatX96ToX10_18();
        return markPrice;
    }

As seen in the code above getPositionValue uses 15 as the TWAP interval. This means it is pulling a 15 second TWAP rather than a 15 minute TWAP as intended.

## Impact

The mark price and by extension the position value will frequently be different from true mark price of the market allowing for larger rebalances than should be possible.

## Code Snippet

https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/integrations/perp/PerpDepository.sol#L708-L713

## Tool used

Manual Review

## Recommendation

I recommend pulling pulling the TWAP fresh each time from ClearingHouseConfig, because the TWAP can be changed at anytime. If it is desired to make it a constant then it should at least be changed from 15 to 900.