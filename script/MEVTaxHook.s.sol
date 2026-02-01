// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import { Script, console } from "forge-std/Script.sol";
import { Hooks } from "v4-core/libraries/Hooks.sol";
import { IPoolManager } from "v4-core/interfaces/IPoolManager.sol";
import { HookMiner } from "v4-periphery/src/utils/HookMiner.sol";

import { MEVTaxHook } from "../src/MEVTaxHook.sol";

/// @notice Mines the address and deploys the MEVTaxHook contract
/// @dev Load config from .env file: `source .env && forge script script/MEVTaxHook.s.sol`
///      Or use per-chain env: `source .env.mainnet && forge script ...`
contract DeployMEVTaxHook is Script {
    address constant CREATE2_DEPLOYER = address(0x4e59b44847b379578588920cA78FbF26c0B4956C);

    function run() public {
        // Load configuration from environment
        string memory rpcUrl = vm.envString("RPC_URL");
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address poolManager = vm.envAddress("POOL_MANAGER");

        // Fork the target chain
        vm.createSelectFork(rpcUrl);

        console.log("RPC:", rpcUrl);
        console.log("Deployer:", vm.addr(deployerPrivateKey));
        console.log("PoolManager:", poolManager);

        // Hook permissions: afterInitialize, beforeSwap, afterSwap
        uint160 flags = uint160(Hooks.AFTER_INITIALIZE_FLAG | Hooks.BEFORE_SWAP_FLAG | Hooks.AFTER_SWAP_FLAG);

        bytes memory constructorArgs = abi.encode(poolManager);

        address hookAddress;
        bytes32 salt;

        // Mine a new salt that will produce a hook address with the correct flags
        (hookAddress, salt) = HookMiner.find(CREATE2_DEPLOYER, flags, type(MEVTaxHook).creationCode, constructorArgs);
        console.log("Mined new salt:", vm.toString(salt));
        console.log("Save this salt to HOOK_SALT env var for redeployment");

        console.log("Deploying MEVTaxHook to:", hookAddress);

        // Deploy the hook using CREATE2
        vm.startBroadcast(deployerPrivateKey);
        MEVTaxHook hook = new MEVTaxHook{ salt: salt }(IPoolManager(poolManager));
        vm.stopBroadcast();

        require(address(hook) == hookAddress, "DeployMEVTaxHook: hook address mismatch");

        console.log("MEVTaxHook deployed successfully at:", address(hook));
    }
}
