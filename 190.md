neumo

medium

# UXDController can receive ETH but there's no way to withdraw it

## Summary
UXDController can receive ETH because it is needed to be able to both deposit and withdraw from the Weth contract, but if a user accidentally sends ether to the controller, there is no way to withdraw it.

## Vulnerability Detail
Contract UXDController has two payable functions, `receive()` and `mintWithEth(uint256 minAmountOut, address receiver)`. The first one is needed to receive ETH from the Weth contract when a user calls `redeemForEth`:
```solidity
...
IWETH9(weth).withdraw(amountOut);
...
```
Because the Weth contract decreases the user balance by `amountOut` and transfers the same amount in ETH to the calling contract.
The second one is used to deposit the ETH passed as `msg.value` in the Weth contract in exchange for WETH, transfer it to the depository and receive UXD tokens in exchange.
Both functions `mintWithEth` and `redeemForEth` transfer out the ETH received as `msg.value` in the same call, so the contract should always have a balance of zero ETH. But nothing prevents (because of the presence of the `receive` function) any user to send ETH to the contract. And in that case, there would be no way to withdraw it and would be stuck there forever.

## Impact
Medium impact because it will not usually happen that a user sends ETH accidentally to the contract, but if he does the funds sent will be irrecoverable.

## Code Snippet
https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/core/UXDController.sol#L89
https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/core/UXDController.sol#L302-L304
https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/core/UXDController.sol#L219-L225

## Tool used
Manual review.


## Recommendation
Add a require in the `receive` function to make sure the caller is the Weth contract.
```solidity
require(msg.sender == address(weth), "FORBIDDEN");
```