HonorLt

high

# Vulnerable GovernorVotesQuorumFraction version

## Summary
The protocol uses an OZ version of contracts that contain a known vulnerability in government contracts.

## Vulnerability Detail
```UXDGovernor``` contract inherits from ```GovernorVotesQuorumFraction```:
```solidity
 contract UXDGovernor is
    ReentrancyGuard,
    Governor,
    GovernorVotes,
    GovernorVotesQuorumFraction,
    GovernorTimelockControl,
    GovernorCountingSimple,
    GovernorSettings
```
An OZ security recommendation has revealed a known vulnerability in this contract: https://github.com/OpenZeppelin/openzeppelin-contracts/security/advisories/GHSA-xrc4-737v-9q75

It was patched in version _4.7.2_, but this protocol uses an older version:
  _"@openzeppelin/contracts": "^4.6.0"_

## Impact
The potential impact is described in the OZ advisory.
This issue was assigned with a severity of High from OZ, so I am sticking with it in this submission.

## Code Snippet

https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/governance/UXDGovernor.sol#L37

## Tool used

Manual Review

## Recommendation
Update the OZ version of contracts to version >=_4.7.2_ or at least follow the workarounds of OZ if not possible otherwise.
