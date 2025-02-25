// SPDX-License-Identifier: GPL-3.0



/// @title The Alps DAO auction house proxy



/*********************************

 * ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ *

 * ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ *

 * ░░░░░░█████████░░█████████░░░ *

 * ░░░░░░██░░░████░░██░░░████░░░ *

 * ░░██████░░░████████░░░████░░░ *

 * ░░██░░██░░░████░░██░░░████░░░ *

 * ░░██░░██░░░████░░██░░░████░░░ *

 * ░░░░░░█████████░░█████████░░░ *

 * ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ *

 * ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ *

 *********************************/



pragma solidity ^0.8.6;



import "./TransparentUpgradeableProxy.sol";



contract AlpsAuctionHouseProxy is TransparentUpgradeableProxy {

    constructor(

        address logic,

        address admin,

        bytes memory data

    ) TransparentUpgradeableProxy(logic, admin, data) {}

}