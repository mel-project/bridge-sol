// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.16;

import 'openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol';

contract ThemelioBridgeProxy is ERC1967Proxy {
    constructor(address _logic, bytes memory _data) ERC1967Proxy(_logic, _data) payable {}
}