keccak123

medium

# Incorrect PerpVETHMarket address in config

## Summary

The address for `PerpVETHMarket` is incorrect in the Optimism mainnet deployment script config file. This value has no way to be changed after initialization, so after PerpDepository is deployed it cannot be reset. The only fix would be to upgrade the contract behind the proxy.

## Vulnerability Detail

The value of `PerpVETHMarket` in config/optimismmainnet.config.ts is 0x36B18618c4131D8564A714fb6b4D2B1EdADc0042, which is the address of the VETH-VUSDC Uniswap pool on Optimism mainnet. Instead this value should be the address of VETH which is 0x8C835DFaA34e2AE61775e80EE29E2c724c6AE2BB. The need to use this VETH address value instead of the Uniswap address can be confirmed by duplicating [the call to `exchange.getSqrtMarkTwapX96` in PerpDepository](https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/integrations/perp/PerpDepository.sol#L721-L722)

Using 0x36B18618c4131D8564A714fb6b4D2B1EdADc0042 reverts
`cast call 0xBd7a3B7DbEb096F0B832Cf467B94b091f30C34ec "getSqrtMarkTwapX96(address, uint32)(uint160)" "0x36B18618c4131D8564A714fb6b4D2B1EdADc0042" 15 --rpc-url https://rpc.ankr.com/optimism`

Using 0x8C835DFaA34e2AE61775e80EE29E2c724c6AE2BB succeeds and returns 2874839871718088358165111131160
`cast call 0xBd7a3B7DbEb096F0B832Cf467B94b091f30C34ec "getSqrtMarkTwapX96(address, uint32)(uint160)" "0x8C835DFaA34e2AE61775e80EE29E2c724c6AE2BB" 15 --rpc-url https://rpc.ankr.com/optimism`

Some external calls like the one to getSqrtMarkTwapX96 would revert. Others would return a zero value, [like in the public getPositionValue](https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/integrations/perp/PerpDepository.sol#L708-L713). This results in getPositionValue always returning zero.

## Impact

Deployment that would set incorrect parameters and therefore some calls would revert. A redeployment on mainnet Optimism would be required, probably by updating PerpDepository because it uses a UUPS proxy.

## Code Snippet

`PerpVETHMarket` in config/optimismmainnet.config.ts
https://github.com/sherlock-audit/2023-01-uxd/blob/main/config/optimismmainnet.config.ts#L31

This value is used when initializing `PerpDepository` and corresponds to `market`
https://github.com/sherlock-audit/2023-01-uxd/blob/main/scripts/optimism/2_deploy_perp_depository.ts
#L38

## Tool used

Manual Review

## Recommendation

Set the value of `PerpVETHMarket` in config/optimismmainnet.config.ts to 0x8C835DFaA34e2AE61775e80EE29E2c724c6AE2BB