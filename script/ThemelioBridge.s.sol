// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.13;

import 'forge-std/Script.sol';
import '../src/ThemelioBridge.sol';
import '../src/ThemelioBridgeProxy.sol';

contract ThemelioBridgeScript is Script {
    function run() external {
        vm.startBroadcast();

        ThemelioBridge implementation = new ThemelioBridge();

        address implementationAddress = address(implementation);
        bytes memory data = abi.encodeWithSelector(
            bytes4(keccak256('initialize(uint256,bytes32,bytes32)')),
            0, // initial block height
            0, // initial transactions hash
            0 // initial stakes hash
        );

        ThemelioBridgeProxy proxy = new ThemelioBridgeProxy(implementationAddress, data);

        vm.stopBroadcast();

        proxy; // removes compiler warning
    }
}