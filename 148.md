koxuan

medium

# storage of upgradeable contracts might become corrupted during an upgrade

## Summary
There are upgradeable contracts that inherit from parent contracts. However, the parent contracts do not contain a gap variable, potentially causing a collision of variables if new variables are added to the parent classes.

## Vulnerability Detail

These are the upgradeable contracts that are at risk of corruptible storage. `UXDController`, `PerpDepository` and `RageDepository`. 

```solidity
contract UXDController is
    UUPSUpgradeable,
    ReentrancyGuardUpgradeable,
    OwnableUpgradeable,
    UXDControllerStorage
{
```

```solidity
contract PerpDepository is
    UUPSUpgradeable,
    OwnableUpgradeable,
    ReentrancyGuardUpgradeable,
    PerpDepositoryStorage
{
```

```solidity
contract RageDnDepository is
    UUPSUpgradeable,
    ReentrancyGuardUpgradeable,
    OwnableUpgradeable,
    RageDnDepositoryStorage
{
```

However, upon looking at their parent classes `UXDControllerStorage`, `PerpDepositoryStorage` and `RageDnDepositoryStorage`, they do not contain a gap variable at the end of their contracts. This means that if new variables are added to `UXDControllerStorage`, `PerpDepositoryStorage` or `RageDnDepositoryStorage` during an upgrade,  the storage of the upgradeable contracts will become corrupted.

Note that PerpDepository has a variable and therefore introducing new variables during an upgrade to PerpDepositoryStorage will cause storage corruption immediately. For UXDController or RageDnDepository, there will only be a storage corruption if a prior upgrade adds new variables to their contracts and a later upgrade adds new variables to their storage contract that they inherit from.

 




## Impact
Storage of upgradeable contracts might become corrupted when upgrading.

## Code Snippet
[UXDController.sol#L19-L24](https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/core/UXDController.sol#L19-L24)
[PerpDepository.sol#L25-L30](https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/integrations/perp/PerpDepository.sol#L25-L30)
[RageDnDepository.sol#L18-L23](https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/integrations/rage-trade/RageDnDepository.sol#L18-L23)
[UXDControllerStorage.sol#L10-L27](https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/core/UXDControllerStorage.sol#L10-L27)
[PerpDepositoryStorage.sol#L11-L64](https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/integrations/perp/PerpDepositoryStorage.sol#L11-L64)
[RageDnDepositoryStorage.sol#L8-L33](https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/integrations/rage-trade/RageDnDepositoryStorage.sol#L8-L33)


## Tool used

Manual Review

## Recommendation

Recommend adding a storage variable at the end of the parent contracts.

```solidity
uint256[50] __gap;
```
