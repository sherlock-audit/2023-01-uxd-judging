StErMi

high

# If `redeemable` is updated in `UXDController` users with the "old" token will not be able to redeem the deposited amount

## Summary

If `redeemable` is updated in `UXDController` users with the "old" token will not be able to redeem the deposited amount 

## Vulnerability Detail

The `UXDController` has a function called `setRedeemable` that allows the controller's owner to update the address of the `redeemable` token (`UXD`). 

When this happens, the users who own the "old" redeemable tokens will not be able anymore to call both `redeem` or `redeemForEth` because those function would use the new token for which the users have zero balance.

## Impact

Users that own the "old" redeemable token will not be able to redeem anymore, converting back `UXD` to the underlying deposited in the past.

## Code Snippet

https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/core/UXDController.sol#L131-L139

## Tool used

Manual Review + foundry test

```solidity
    // When the owner of the UXDController update the reedeable address
    // All the users that own the "old" token will not be able to redeem it anymore
    // Because they have zero balance of the new reedemable token
    function testChangeReedemable() public {
        uint256 amount = 1 ether;

        // alice mint some UXD token
        uint256 uxdAmount = deposit(alice, address(asset), amount, 0);
        uint256 aliceAssetBalanceAfterDeposit = asset.balanceOf(alice);
        assertEq(redeemable.balanceOf(alice), uxdAmount);

        vm.startPrank(admin);
        TestERC20 redeemableNew = new TestERC20("RedeemableNew", "REDN");
        controller.setRedeemable(address(redeemableNew));
        vm.stopPrank();

        // Alice own zero of the new reedemable token
        assertEq(redeemableNew.balanceOf(alice), 0);

        // alice approve 1 ether of both tokens
        // but she owns zero of the new one because the deposited has happened when
        // the "old" reedemable token was used by the UXDController
        vm.startPrank(alice);
        redeemable.approve(address(controller), amount);
        redeemableNew.approve(address(controller), amount);
        vm.stopPrank();

        // this call will revert because "ERC20: burn amount exceeds balance". Alice do not own the new Redeemable (UXD) token
        // she only owns the old UXD token without a proper way to redeem it again
        vm.expectRevert(bytes("ERC20: burn amount exceeds balance"));
        redeem(alice, address(asset), uxdAmount, 0);

        // Her balance remained the same because no underlying has been redeemed
        assertEq(asset.balanceOf(alice), aliceAssetBalanceAfterDeposit);
    }
```

Full test here: https://github.com/sherlock-audit/2023-01-uxd/blob/main/test/foundry/SControllerIssue2.t.sol

## Recommendation

1) Remove the function that allows the `owner` of the controller to update the redeemable token if not needed

If this is not the case, the protocol should be very specific to explain why it's needed and which are the risks. It should also think about a procedure to allow the update of the address only when there's no supply left of the old redeemable token.
