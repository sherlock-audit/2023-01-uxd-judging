cccz

medium

# UXDGovernor should override transferETH function

## Summary
UXDGovernor should override transferETH function
## Vulnerability Detail
The UXDGovernor contract inherits the UXDTimelockController contract.
In the UXDTimelockController contract, the transferETH/approveERC20/transferERC20 functions all have the onlySelf modifier, which means that these functions can only be called by this contract.
In the UXDGovernor contract, the approveERC20/transferERC20 function is rewritten, and onlySelf is replaced by onlyGovernance, but the transferETH function is not rewritten, which makes the UXDGovernor contract may not be able to use the transferETH function to send ETH in the contract
## Impact
It makes the UXDGovernor contract may not be able to use the transferETH function to send ETH in the contract

## Code Snippet
https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/governance/UXDTimelockController.sol#L40-L66
https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/governance/UXDGovernor.sol#L193-L216
## Tool used

Manual Review

## Recommendation
Consider rewriting transferETH function in UXDGovernor contract and use onlyGovernance instead of onlySelf
```solidity
    function transferETH(address payable to, uint256 amount) external onlyGovernance nonReentrant {
        // solhint-disable-next-line avoid-low-level-calls
        (bool success,) = to.call{value: amount}("");
        require(success, "Failed to send ETH");
    }
```