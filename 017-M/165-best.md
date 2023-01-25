keccak123

medium

# Cannot redeem UXD for stablecoin on Optimism

## Summary

At a high level, the goal of the UXD protocol is to ensure the stability of the UXD stablecoin. The current design of UXDController means that a user can deposit USDC to receive UXD, maintaining their exposure to stable assets. The problem is that UXDController will revert if a user calls `redeem` to request their USDC stablecoin back and the assigned depository is PerpDepository. If USDC cannot be redeemed, a user cannot exchange their UXD for a stable asset, and is only able to acquire a volatile asset like WETH in return for their UXD, which removes a key benefit of the stability that most UXD users seek.

## Vulnerability Detail

The `redeem` in PerpDepository will revert if `asset == quoteToken`. This an important option to enable and NOT have revert, because it allows users to receive USDC in return for their UXD when withdrawing and avoid exposure to volatile assets. [Because of the commented out code](https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/integrations/perp/PerpDepository.sol#L273-L274), completing this code may be an unfinished TODO and should see completion before launch to enable deposits and also redemptions to happen with USDC.

## Impact

A user cannot receive a stable asset with PerpDepository when redeeming their stablecoin and can only receive the volatile asset WETH

## Code Snippet

Revert case in `redeem`
https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/integrations/perp/PerpDepository.sol#L273-L274

## Tool used

Manual Review

## Recommendation

Implement the `asset == quoteToken` case of `redeem` in PerpDepository instead of reverting.