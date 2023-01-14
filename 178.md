Zarf

medium

# netAssetDeposits not properly tracked in PerpDepository.sol

## Summary

The amount of asset tokens deposited in the vault is not properly tracked in the `PerpDepository` contract.

## Vulnerability Detail

`_rebalanceNegativePnlLite` and `_rebalanceNegativePnlWithSwap` in `PerpDepository` both pull asset tokens from the vault but do not update the `netAssetDeposits` variable which keeps track of the amount of asset tokens deposited in the vault.

## Impact

If the PnL is negative and a rebalance is performed, assets will be pulled from the vault but `netAssetDeposits` will not be reduced. Therefore, the `netAssetDeposits` will be higher than the actual amount of asset tokens in the vault. 

This might lead to issues when performing `redeem()` as redeeming UXD for the asset tokens calls `_withdrawAsset()` and checks whether the amount to withdraw is not higher than `netAssetDeposits`:

```solidity
function _withdrawAsset(uint256 amount, address to) private {
    if (amount > netAssetDeposits) {
        revert InsufficientAssetDeposits(netAssetDeposits, amount);
    }
    netAssetDeposits -= amount;

    vault.withdraw(address(assetToken), amount);
    IERC20(assetToken).transfer(to, amount);
}
```

In case ‘actual asset amount’  < `amount` < `netAssetDeposits`, the function will revert upon withdrawal from the vault. Hence it cannot be abused to steal more funds. 

However, `netAssetDeposits` is also part of the DepositoryState: 

```solidity
function getCurrentState() external view returns (DepositoryState memory) {
  return
      DepositoryState({
          netAssetDeposits: netAssetDeposits,
          insuranceDeposited: insuranceDeposited,
          redeemableUnderManagement: redeemableUnderManagement,
          totalFeesPaid: totalFeesPaid,
          redeemableSoftCap: redeemableSoftCap
      });
}
```

Other protocols interacting the the depository or with UXD protocol might use this variable to track the solvency of the protocol, leading to unexpected results.

## Code Snippet

[https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/integrations/perp/PerpDepository.sol#L498](https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/integrations/perp/PerpDepository.sol#L498)

[https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/integrations/perp/PerpDepository.sol#L638](https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/integrations/perp/PerpDepository.sol#L638)

## Tool used

Manual Review

## Recommendation

Update the `netAssetDeposits` when pulling funds from the vault during a rebalance:

```solidity
function _rebalanceNegativePnlWithSwap(
    uint256 amount,
    uint256 amountOutMinimum,
    uint160 sqrtPriceLimitX96,
    uint24 swapPoolFee,
    address account
) private returns (uint256, uint256) {
    ...
		netAssetDeposits -= baseAmount;
    vault.withdraw(assetToken, baseAmount);
    ...
}
```