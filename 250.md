0x52

high

# USDC deposited to PerpDepository.sol are irretrievable and effectively causes UDX to become undercollateralized

## Summary

PerpDepository rebalances negative PNL into USDC holdings. This preserves the delta neutrality of the system by exchanging base to quote. This is problematic though as once it is in the vault as USDC it can never be withdrawn. The effect is that the delta neutral position can never be liquidated but the USDC is inaccessible so UDX is effectively undercollateralized. 

## Vulnerability Detail

`_processQuoteMint`, `_rebalanceNegativePnlWithSwap` and `_rebalanceNegativePnlLite` all add USDC collateral to the system. There were originally two ways in which USDC could be removed from the system. The first was positive PNL rebalancing, which has now been deactivated. The second is for the owner to remove the USDC via `withdrawInsurance`.

    function withdrawInsurance(uint256 amount, address to)
        external
        nonReentrant
        onlyOwner
    {
        if (amount == 0) {
            revert ZeroAmount();
        }

        insuranceDeposited -= amount;

        vault.withdraw(insuranceToken(), amount);
        IERC20(insuranceToken()).transfer(to, amount);

        emit InsuranceWithdrawn(msg.sender, to, amount);
    }

The issue is that `withdrawInsurance` cannot actually redeem any USDC. Since insuranceDeposited is a uint256 and is decremented by the withdraw, it is impossible for more USDC to be withdrawn then was originally deposited.

The result is that there is no way for the USDC to ever be redeemed and therefore over time will lead to the system becoming undercollateralized due to its inaccessibility.

## Impact

UDX will become undercollateralized and the ecosystem will spiral out of control

## Code Snippet

https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/integrations/perp/PerpDepository.sol#L478-L528

https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/integrations/perp/PerpDepository.sol#L615-L644

https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/integrations/perp/PerpDepository.sol#L385-L397

## Tool used

Manual Review

## Recommendation

Allow all USDC now deposited into the insurance fund to be redeemed 1:1