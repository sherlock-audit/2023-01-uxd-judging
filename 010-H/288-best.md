0x52

high

# PerpDespository#reblance and rebalanceLite can be called to drain funds from anyone who has approved PerpDepository

## Summary

PerpDespository#reblance and rebalanceLite allows anyone to specify the account that pays the quote token. These functions allow a malicious user to abuse any allowance provided to PerpDirectory. rebalance is the worst of the two because the malicious user could sandwich attack the rebalance to steal all the funds and force the unsuspecting user to pay the `shortfall`.

## Vulnerability Detail

    function rebalance(
        uint256 amount,
        uint256 amountOutMinimum,
        uint160 sqrtPriceLimitX96,
        uint24 swapPoolFee,
        int8 polarity,
        address account // @audit user specified payer
    ) external nonReentrant returns (uint256, uint256) {
        if (polarity == -1) {
            return
                _rebalanceNegativePnlWithSwap(
                    amount,
                    amountOutMinimum,
                    sqrtPriceLimitX96,
                    swapPoolFee,
                    account // @audit user address passed directly
                );
        } else if (polarity == 1) {
            // disable rebalancing positive PnL
            revert PositivePnlRebalanceDisabled(msg.sender);
            // return _rebalancePositivePnlWithSwap(amount, amountOutMinimum, sqrtPriceLimitX96, swapPoolFee, account);
        } else {
            revert InvalidRebalance(polarity);
        }
    }

`rebalance` is an unpermissioned function that allows anyone to call and rebalance the PNL of the depository. It allows the caller to specify the an account that passes directly through to `_rebalanceNegativePnlWithSwap`

    function _rebalanceNegativePnlWithSwap(
        uint256 amount,
        uint256 amountOutMinimum,
        uint160 sqrtPriceLimitX96,
        uint24 swapPoolFee,
        address account
    ) private returns (uint256, uint256) {
        ...
        // @audit this uses user supplied swap parameters which can be malicious
        SwapParams memory params = SwapParams({
            tokenIn: assetToken,
            tokenOut: quoteToken,
            amountIn: baseAmount,
            amountOutMinimum: amountOutMinimum,
            sqrtPriceLimitX96: sqrtPriceLimitX96,
            poolFee: swapPoolFee
        });
        uint256 quoteAmountOut = spotSwapper.swapExactInput(params);
        int256 shortFall = int256(
            quoteAmount.fromDecimalToDecimal(18, ERC20(quoteToken).decimals())
        ) - int256(quoteAmountOut);
        if (shortFall > 0) {
            // @audit shortfall is taken from account specified by user
            IERC20(quoteToken).transferFrom(
                account,
                address(this),
                uint256(shortFall)
            );
        } else if (shortFall < 0) {
            ...
        }
        vault.deposit(quoteToken, quoteAmount);

        emit Rebalanced(baseAmount, quoteAmount, shortFall);
        return (baseAmount, quoteAmount);
    }

`_rebalanceNegativePnlWithSwap` uses both user specified swap parameters and takes the shortfall from the account specified by the user. This is where the function can be abused to steal funds from any user that sets an allowance for this contract. A malicious user can sandwich attack the swap and specify malicious swap parameters to allow them to steal the entire rebalance. This creates a large shortfall which will be taken from the account that they specify, effectively stealing the funds from the user. 

Example:
Any account that gives the depository allowance can be stolen from. Imagine the following scenario. The multisig is going to rebalance the contract for 15000 USDC worth of ETH and based on current market conditions they are estimating that there will be a 1000 USDC shortfall because of the difference between the perpetual and spot prices (divergences between spot and perpetual price are common in trending markets). They first approve the depository for 1000 USDC. A malicious user sees this approval and immediately submits a transaction of their own. They request to rebalance only 1000 USDC worth of ETH and sandwich attack the swap to steal the rebalance. They specify the multisig as `account` and force it to pay the 1000 USDC shortfall and burn their entire allowance, stealing the USDC.

## Impact

Anyone that gives the depository allowance can easily have their entire allowance stolen

## Code Snippet

https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/integrations/perp/PerpDepository.sol#L478-L528

## Tool used

Manual Review

## Recommendation

PerpDespository#reblance and rebalanceLite should use msg.sender instead of account:

         function rebalance(
            uint256 amount,
            uint256 amountOutMinimum,
            uint160 sqrtPriceLimitX96,
            uint24 swapPoolFee,
            int8 polarity,
    -       address account
        ) external nonReentrant returns (uint256, uint256) {
            if (polarity == -1) {
                return
                    _rebalanceNegativePnlWithSwap(
                        amount,
                        amountOutMinimum,
                        sqrtPriceLimitX96,
                        swapPoolFee,
    -                   account 
    +                   msg.sender
                    );
            } else if (polarity == 1) {
                // disable rebalancing positive PnL
                revert PositivePnlRebalanceDisabled(msg.sender);
                // return _rebalancePositivePnlWithSwap(amount, amountOutMinimum, sqrtPriceLimitX96, swapPoolFee, account);
            } else {
                revert InvalidRebalance(polarity);
            }
        }