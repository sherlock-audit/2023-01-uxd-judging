0x52

medium

# Assets in depositories will become inaccessible when they are unregistered

## Summary

unregisterDepository will trap all collateral currently in the depository leaving UXD undercollateralized. 

## Vulnerability Detail

    function unregisterDepository(address depository, address assetToken)
        external
        onlyOwner
    {
        bool foundByAsset = false;
        address[] storage byAsset = _depositoriesForAsset[assetToken];
        if (byAsset.length == 0) {
            revert NotExists(assetToken);
        }
        for (uint256 i = 0; i < byAsset.length; i++) {
            if (byAsset[i] == depository) {
                foundByAsset = true;
                byAsset[i] = byAsset[byAsset.length - 1];
                byAsset.pop();
                break;
            }
        }
        if (!foundByAsset) {
            revert NotExists(assetToken);
        }
        emit DepositoryUnregistered(assetToken, depository);
    }

UXDRouter#unregisterDepository allows the owner to unregister any depository causing all collateral in the depository to become irretrievable.

## Impact

Assets in unregistered depositories will be inaccessible causing UXD to become partially undercollateralized

## Code Snippet

https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/core/UXDRouter.sol#L59-L81

## Tool used

Manual Review

## Recommendation

There are a few potential ways to address this issue:
1) Disallow depositories from being removed all together and allow depositories to be placed in withdraw only mode
2) Allow depositories to be migrated by the controller or multisig
3) Allow removal of depositories but only if they do not contain any assets