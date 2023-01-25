0x52

medium

# PerpDepository#_rebalanceNegativePnlWithSwap fails to approve vault for quote deposit

## Summary

Throughout the entirety of the contract it grants approval to the vault before depositing either quote or asset. In this case there is no approval which means that the deposit call will fail causing PerpDepository#_rebalanceNegativePnlWithSwap to always revert.

## Vulnerability Detail

See summary.

## Impact

PerpDepository#_rebalanceNegativePnlWithSwap won't function

## Code Snippet

https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/integrations/perp/PerpDepository.sol#L478-L528

## Tool used

Manual Review

## Recommendation

Add the missing approve call:

        } else if (shortFall < 0) {
            // we got excess tokens in the spot swap. Send them to the account paying for rebalance
            IERC20(quoteToken).transfer(
                account,
                _abs(shortFall)
            );
        }

    +   IERC20(quoteToken).approve(address(vault), quoteAmount); 
        vault.deposit(quoteToken, quoteAmount);

        emit Rebalanced(baseAmount, quoteAmount, shortFall);
        return (baseAmount, quoteAmount);