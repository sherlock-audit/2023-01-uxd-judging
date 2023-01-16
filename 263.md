0xmuxyz

high

# A miscalculated-amount will be returned from the both `_assetsToRedeemable()` function and `_redeemableToAssets()`function due to that the number of decimals is not standardized

## Summary
A miscalculated-amount will be returned from the both `_assetsToRedeemable()` function and `_redeemableToAssets()`function due to that the number of decimals is not standardized.

## Vulnerability Detail
- The `_assetsToRedeemable()` function is defined in order to return the amount of `UXD` that is converted from `USDC` .
[RageDnDepository.sol#L178-L181](https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/integrations/rage-trade/RageDnDepository.sol#L178-L181)
```solidity
    function _assetsToRedeemable(uint256 assetAmount)  /// @audit: USDC -> UXD
        private
        view
        returns (uint256)
    {
        return
            assetAmount.fromDecimalToDecimal(  /// @audit - Here is a target 
                IERC20Metadata(assetToken).decimals(),
                IERC20Metadata(redeemable).decimals()
            );
    }
```

- The `_redeemableToAssets()` function is defined in order to return the amount of `USDC` that is converted from `UXD` .
[RageDnDepository.sol#L190-L193](https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/integrations/rage-trade/RageDnDepository.sol#L190-L193)
```solidity
    function _redeemableToAssets(uint256 redeemableAmount)  /// @audit: UXD -> USDC
        private
        view
        returns (uint256)
    {
        return
            redeemableAmount.fromDecimalToDecimal(    /// @audit - Here is a target 
                IERC20Metadata(redeemable).decimals(),
                IERC20Metadata(assetToken).decimals()
            );
    }
```

- The `fromDecimalToDecimal()` function is used for the calculation in the both `_assetsToRedeemable()` function and `_redeemableToAssets()` function above.
[MathLib.sol#L9-L11](https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/libraries/MathLib.sol#L9-L11)
```solidity
    function fromDecimalToDecimal(uint256 amount, uint8 inDecimals, uint8 outDecimals) internal pure returns (uint256) {
        return amount * 10 ** outDecimals / 10 ** inDecimals;
    }
```


According to the[ documentation](https://docs.uxd.fi/uxdprogram-ethereum/) like below, both `USDC` and `UXD` are `USD-pegged stablecoin` . 
> Users deposit crypto assets such as ETH and USDC to mint UXD. UXD token holders can at any time retrieve ~1USD worth of assets for each UXD burned.

Thus, `UXD` is pretty much equal to `USDC`. It means that `1 UXD` is supposed to be converted to `1 USDC` . Likewise, `1 USDC` is supposed to be converted to `1 UXD` .

On the other hand, the number of decimals of each tokens ( `UXD` and `USDC` ) is different.
- UXD is a `18` decimals token.
- USDC is a `6` decimals token.

At the moment, the difference of the number of decimals between `UXD` and `USDC` above is not considered for the calculation of returned-value in the both `_assetsToRedeemable()` function and `_redeemableToAssets()` function.

This lead to that the miscalculated-amount will be returned from the both `_assetsToRedeemable()` function and `_redeemableToAssets()` function.

Example 1). 
- Let's say the `assetToken` is `USDC` and the `redeemable` is `UXD` in the `_assetsToRedeemable()` function.
- if `1 USDC` is assigned into the parameter of `"assetToken"`  in the `_assetsToRedeemable()` function, actual calculation is like below:
```solidity
1 * 10 ** 6 / 10 ** 18
```
As a result, the result of this calculation for returned-value above will be `"underflow"` . 


Example 2). 
- Let's say the `redeemable` is `UXD` and `assetToken` is `USDC` in the `_redeemableToAssets()` function. 
- If `1 UXD` is assigned into the parameter of `"redeemable"` in the `_redeemableToAssets()` function, actual calculation is like this:
```solidity
1 * 10 ** 18 / 10 ** 6
```
As a result, the `1e12x` times larger amount of USDC than the actual amount is returned from the `_redeemableToAssets()` function. 


## Impact
This vulnerability lead to that a miscalculated-amount will be returned from the both `_assetsToRedeemable()` function and `_redeemableToAssets()` function.

## Code Snippet
- https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/integrations/rage-trade/RageDnDepository.sol#L178-L181
- https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/integrations/rage-trade/RageDnDepository.sol#L190-L193
- https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/libraries/MathLib.sol#L9-L11

## Tool used
Manual Review

## Recommendation
Consider adding code like below to both functions in order to standardize the number of decimals before the calculation for returned-value is executed.
- _assetsToRedeemable()
```solidity
    function _assetsToRedeemable(uint256 assetAmount)  /// @audit: USDC -> UXD
        private
        view
        returns (uint256)
    {
        return
            assetAmount.fromDecimalToDecimal(  
                IERC20Metadata(assetToken).decimals() * (10 ** (18 - IERC20Metadata(assetToken).decimals())),   /// @audit - standardize the number of decimals of "assetToken".
                IERC20Metadata(redeemable).decimals() * (10 ** (18 - IERC20Metadata(redeemable).decimals()))  /// @audit - standardize the number of decimals of "redeemable".
            );
    }
```
- _redeemableToAssets()
```solidity
    function _redeemableToAssets(uint256 redeemableAmount)  /// @audit: UXD -> USDC
        private
        view
        returns (uint256)
    {
        return
            redeemableAmount.fromDecimalToDecimal(
                IERC20Metadata(redeemable).decimals() * (10 ** (18 - IERC20Metadata(redeemable).decimals())),  /// @audit - standardize the number of decimals of "redeemable"
                IERC20Metadata(assetToken).decimals() * (10 ** (18 - IERC20Metadata(assetToken).decimals()))   /// @audit - standardize the number of decimals of "assetToken".
            );
    }
```