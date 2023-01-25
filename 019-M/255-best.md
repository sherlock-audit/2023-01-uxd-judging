0x52

medium

# Only one depository is accessible for each asset limiting each asset to only one

## Summary

UXDRouter is designed to support multiple depositories but the way the view functions are setup, only the first depository added is actually accessible. This dramatically limits the ability of the protocol to expand and to migrate to new depositories.

## Vulnerability Detail

    function findDepositoryForDeposit(address assetToken, uint256) external view returns (address) {
        return _firstDepositoryForAsset(assetToken);
    }

    function findDepositoryForRedeem(address assetToken, uint256) external view returns (address) {
        return _firstDepositoryForAsset(assetToken);
    }

UXDController uses the above functions to find and return the proper depository to redeem from / mint to. The problem is that it just always returns the first depository registered for each assetToken. This means that all other registered depositories are inaccessible. 

## Impact

All depositories but the first one registered are inaccessible and can never receive a deposit or redeem request

## Code Snippet

https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/core/UXDRouter.sol#L101-L107

## Tool used

Manual Review

## Recommendation

I cannot make a recommendation since it is unclear to me how this is meant to work but the designed should be reviewed and a method for determining the proper depository should be implemented