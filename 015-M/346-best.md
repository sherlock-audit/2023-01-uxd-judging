berndartmueller

medium

# Inaccurate Perp debt calculation

## Summary

The anticipated Perp account debt value calculation via `PerpDepository.getDebtValue` is inaccurate and does not incorporate the (not yet settled) owed realized PnL `owedRealizedPnl`.

## Vulnerability Detail

The `PerpDepository.getDebtValue` function calculates the account debt value by subtracting the pending funding payments and fees from the quote token balance and unrealized PnL. However, the owed realized PnL (`owedRealizedPnl`) is not considered in the calculation. The owed realized PnL is the realized PnL owed to the account but has **not yet been settled**.

Perp provides the `Vault.getSettlementTokenValue()` function to calculate the settlement token value of an account and uses it to determine the accounts' debt (if < 0, [see docs](https://docs.perp.com/docs/contracts/Vault/#getsettlementtokenvalue)). For example, it is used to determine if an account is liquidable - see [Vault.isLiquidatable#L434](https://github.com/perpetual-protocol/perp-curie-contract/blob/27ea8e2c4be37d1dd58c1eed3b3cc269d398a091/contracts/Vault.sol#L434)

Perps' specs define the value of an account as ([see here for reference](https://support.perp.com/hc/en-us/articles/5331515119001)):

$$
\begin{aligned} accountValue &= \underbrace{collateral + owedRealizedPnl + pendingFundingPayment + pendingFee}_{totalCollateralValue} + \underbrace{\sum_{market}{unrealizedPnl_{market}}}_{totalUnrealizedPnl} \end{aligned}
$$

## Impact

The Perp account debt calculation is inaccurate and deviates from the calculation by the Perp protocol itself. Even though the `PerpDepository.getDebtValue` function is `external`, it could lead to issues when querying from another contract or off-chain to use as decision criteria or manifest as a serious issue when used in an upgraded version of the contract.

## Code Snippet

[integrations/perp/PerpDepository.sol#L773](https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/integrations/perp/PerpDepository.sol#L773)

```solidity
/// @notice Get the quote token balance of this user
/// @dev THe total debt is computed as:
///     quote token balance + unrealized PnL - Pending fee - pending funding payments
/// @param account The account to return the debt for
/// @return debt The account debt, or zero if no debt.
function getDebtValue(address account) external view returns (uint256) {
    IAccountBalance perpAccountBalance = IAccountBalance(
        clearingHouse.getAccountBalance()
    );
    IExchange perpExchange = IExchange(clearingHouse.getExchange());
    int256 accountQuoteTokenBalance = vault.getBalance(account);
    if (accountQuoteTokenBalance < 0) {
        revert InvalidQuoteTokenBalance(accountQuoteTokenBalance);
    }
    int256 fundingPayment = perpExchange.getAllPendingFundingPayment(
        account
    );
    uint256 quoteTokenBalance = uint256(accountQuoteTokenBalance)
        .fromDecimalToDecimal(ERC20(quoteToken).decimals(), 18);
    (
        , // @audit-info `owedRealizedPnl` is omitted here and missing in the calculation below
        int256 perpUnrealizedPnl,
        uint256 perpPendingFee
    ) = perpAccountBalance.getPnlAndPendingFee(account);
    int256 debt = int256(quoteTokenBalance) +
        perpUnrealizedPnl -
        int256(perpPendingFee) -
        fundingPayment;
    return (debt > 0) ? 0 : _abs(debt);
}
```

[Vault.\_getSettlementTokenValue](https://github.com/perpetual-protocol/perp-curie-contract/blob/27ea8e2c4be37d1dd58c1eed3b3cc269d398a091/contracts/Vault.sol#L880-L884)

`Vault._getSettlementTokenValue` is called internally by Perp's public `Vault.getSettlementTokenValue()` function.

```solidity
function _getSettlementTokenValue(address trader) internal view returns (int256 settlementTokenValueX10_18) {
    (int256 settlementBalanceX10_18, int256 unrealizedPnlX10_18) =
        _getSettlementTokenBalanceAndUnrealizedPnl(trader);
    return settlementBalanceX10_18.add(unrealizedPnlX10_18);
}
```

[Vault.\_getSettlementTokenBalanceAndUnrealizedPnl](https://github.com/perpetual-protocol/perp-curie-contract/blob/27ea8e2c4be37d1dd58c1eed3b3cc269d398a091/contracts/Vault.sol#L852-L877)

```solidity
/// @notice Get the specified trader's settlement token balance, including pending fee, funding payment,
///         owed realized PnL, but without unrealized PnL)
/// @dev Note the difference between the return argument`settlementTokenBalanceX10_18` and
///      the return value of `getSettlementTokenValue()`.
///      The first one is settlement token balance with pending fee, funding payment, owed realized PnL;
///      The second one is the first one plus unrealized PnL.
/// @return settlementTokenBalanceX10_18 Settlement amount in 18 decimals
/// @return unrealizedPnlX10_18 Unrealized PnL in 18 decimals
function _getSettlementTokenBalanceAndUnrealizedPnl(address trader)
    internal
    view
    returns (int256 settlementTokenBalanceX10_18, int256 unrealizedPnlX10_18)
{
    int256 fundingPaymentX10_18 = IExchange(_exchange).getAllPendingFundingPayment(trader);

    int256 owedRealizedPnlX10_18;
    uint256 pendingFeeX10_18;
    (owedRealizedPnlX10_18, unrealizedPnlX10_18, pendingFeeX10_18) = IAccountBalance(_accountBalance)
        .getPnlAndPendingFee(trader);

    settlementTokenBalanceX10_18 = getBalance(trader).parseSettlementToken(_decimals).add(
        pendingFeeX10_18.toInt256().sub(fundingPaymentX10_18).add(owedRealizedPnlX10_18) // @audit-info owed realized PnL is added here
    );

    return (settlementTokenBalanceX10_18, unrealizedPnlX10_18);
}
```

## Tool used

Manual Review

## Recommendation

Consider using the `Vault.getSettlementTokenValue()` function to determine the accounts' debt ([see docs](https://docs.perp.com/docs/contracts/Vault/#getsettlementtokenvalue)).
