duc

high

# Deposit and withdraw to the vault with the wrong decimals of amount in contract `PerpDepository`

## Summary
Function `vault.deposit` and `vault.withdraw` of vault in contract `PerpDepository` need to be passed with the amount in raw decimal of tokens (is different from 18 in case using USDC, WBTC, ... as base and quote tokens). But some calls miss the conversion of decimals from 18 to token's decimal, and pass wrong decimals into them.
## Vulnerability Detail
* Function `vault.deposit` need to be passed the param amount in token's decimal (as same as `vault.withdraw`). You can see at function `_depositAsset` in contract PerpDepository.
```solidity=
function _depositAsset(uint256 amount) private {
    netAssetDeposits += amount;
    
    IERC20(assetToken).approve(address(vault), amount);
    vault.deposit(assetToken, amount);
}
```
* But there are some calls of `vault.deposit` and `vault.withdraw` that passed the amount in the wrong decimal (18 decimal).
Let's see function `_rebalanceNegativePnlWithSwap` in contract PerpDepository:
```solidity=
function _rebalanceNegativePnlWithSwap(
    uint256 amount,
    uint256 amountOutMinimum,
    uint160 sqrtPriceLimitX96,
    uint24 swapPoolFee,
    address account
) private returns (uint256, uint256) {
    ...
    (uint256 baseAmount, uint256 quoteAmount) = _placePerpOrder(
        normalizedAmount,
        isShort,
        amountIsInput,
        sqrtPriceLimitX96
    );
    vault.withdraw(assetToken, baseAmount); 
    
    ...
    
    vault.deposit(quoteToken, quoteAmount);

    emit Rebalanced(baseAmount, quoteAmount, shortFall);
    return (baseAmount, quoteAmount);
}
```
Because function `_placePerpOrder` returns in decimal 18 (confirmed with sponsor WarTech), this calls pass `baseAmount` and `quoteAmount` in decimal 18, inconsistent with the above call. It leads to vault using the wrong decimal when depositing and withdrawing tokens.
* There is  another case that use `vault.withdraw` with the wrong decimal (same as this case) in function `_rebalanceNegativePnlLite`:
```solidity=
//function _rebalanceNegativePnlLite, contract PerpDepository
...

(uint256 baseAmount, uint256 quoteAmount) = _placePerpOrder(
    normalizedAmount,
    isShort,
    amountIsInput,
    sqrtPriceLimitX96
);
vault.withdraw(assetToken, baseAmount);

...
```
## Impact
Because of calling `vault.deposit` and `vault.withdraw` with the wrong decimal of the param amount, the protocol can lose a lot of funds. And some functionalities of the protocol can be broken cause it can revert by not enough allowance when calling these functions.
## Code Snippet
https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/integrations/perp/PerpDepository.sol#L498
https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/integrations/perp/PerpDepository.sol#L524
https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/integrations/perp/PerpDepository.sol#L638
## Tool used

Manual Review

## Recommendation
Should convert the param `amount` from token's decimal to decimal 18 before `vault.deposit` and `vault.withdraw`.