HonorLt

medium

# Redeem only whitelisted assets

## Summary
Only whitelisted assets can be redeemed which does not sound fair to the users.

## Vulnerability Detail
```solidity
    function _redeem(InternalRedeemParams memory redeemParams)
        internal
        returns (uint256)
    {
        if (!whitelistedAssets[redeemParams.assetToken]) {
            revert CtrlNotWhitelisted(redeemParams.assetToken);
        }
    ....
```
If the asset is removed from the whitelist, users are not able to redeem it any more.

As far as I understand, the whitelist is mostly needed to control allowed assets when depositing.
If you want to block new mints of this asset, you remove it from the whitelist, but this way you also block the redemptions. Because these blocked assets still back the redeemable token, some users might be unable to redeem their tokens.

I believe if the asset is no longer in the whitelist, it should forbid new mints, but not redeems.

## Impact
If the users minted some tokens and later the underlying asset was removed from the whitelist, these users might experience blocked withdrawals or they will have to choose other whitelisted assets supposedly there is enough liquidity.

There is no easy way to forbid new deposits without disabling withdrawals also.

## Code Snippet

https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/core/UXDController.sol#L311-L318

## Tool used

Manual Review

## Recommendation
Remove whitelist check in redeem, only check it when depositing new assets. 
