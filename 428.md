ak1

high

# PerpDepository.sol, RageDnDepository.sol : UXD contract would not function when the perp/rage vaults are paused.

## Summary

Any asset whitelisted by owner can be deposited in to vaults like Perp, Rage and then withdraw.

When we look at the deposit and withdraw from perp-curie vault, both are under the whenNotPaused modifier.

`deposit`

    function deposit(address token, uint256 amount)
        external
        override
        whenNotPaused
        nonReentrant
        onlySettlementOrCollateralToken(token)
    {

`withdraw`

    function withdraw(address token, uint256 amount)
        external
        override
        whenNotPaused
        nonReentrant
        onlySettlementOrCollateralToken(token)
    {

Incase of any emergency or any other reason, when the DEXs pauses the operation, then the UXD implementation would be halted.
and other functions would suffer due to this which need to be explored in deep. 

## Vulnerability Detail

PerpDepository.sol , RageDnDepository.sol contract used deposit and withdraw from respective protocol. 

When the Perp and Rage has pause mechanism but UXD does not have.

## Impact

When perp or rage vault 's deposit, withdraw is paused, then the UXD's functionality would suffer and it would bring unexpected results.

## Code Snippet

As an example, Perp vault's deposit

https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/integrations/perp/PerpDepository.sol#L240-L253

## Tool used

Manual Review

## Recommendation

Follow the Perp , Rage vault implementation and use `pause` for critical user interaction functions like deposit, withdraw, redeem.
