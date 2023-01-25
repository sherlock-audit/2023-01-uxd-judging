keccak123

high

# User specified slippage allows frontrunning

## Summary

`rebalance` and `rebalanceLite` can be called by any user. Assets are taken from a user specified `account` address which has approved PerpDepository. If an address has a non-zero approval for PerpDepository, a frontrunner can use `rebalance` to transfer funds and profit by sandwiching the Uniswap pool swap.

## Vulnerability Detail

When `mint` or `redeem` is called in UXDController, `msg.sender` is where the value is coming from. But `rebalance` allows for the caller to specify [the `account` where funds are coming from](https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/integrations/perp/PerpDepository.sol#L452). This means `msg.sender` can be any address. This allows for different scenarios where a frontrunner can profit with these steps.
1. a frontrunner detects a call of `rebalance` transaction in the mempool for a certain account address
2. the frontrunner duplicates the transaction but increases the gas amount (to allow frontrunning the original transaction) and changes the `amountOutMinimum` value to zero
3. the frontrunner can profit by sandwiching the Uniswap swap which now has no slippage setting
4. The user will lose value 

## Impact

An account that is used in `rebalance` can lose value

## Code Snippet

`rebalance` can be frontrun
https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/integrations/perp/PerpDepository.sol#L446

## Tool used

Manual Review

## Recommendation

`rebalance` and `rebalanceLite` should use `msg.sender` to replace the function argument account address.