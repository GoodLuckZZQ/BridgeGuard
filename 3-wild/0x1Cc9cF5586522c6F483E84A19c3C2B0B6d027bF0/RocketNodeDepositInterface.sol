/**

  *       .

  *      / \

  *     |.'.|

  *     |'.'|

  *   ,'|   |`.

  *  |,-'-|-'-.|

  *   __|_| |         _        _      _____           _

  *  | ___ \|        | |      | |    | ___ \         | |

  *  | |_/ /|__   ___| | _____| |_   | |_/ /__   ___ | |

  *  |    // _ \ / __| |/ / _ \ __|  |  __/ _ \ / _ \| |

  *  | |\ \ (_) | (__|   <  __/ |_   | | | (_) | (_) | |

  *  \_| \_\___/ \___|_|\_\___|\__|  \_|  \___/ \___/|_|

  * +---------------------------------------------------+

  * |  DECENTRALISED STAKING PROTOCOL FOR ETHEREUM 2.0  |

  * +---------------------------------------------------+

  *

  *  Rocket Pool is a first-of-its-kind ETH2 Proof of Stake protocol, designed to be community owned,

  *  decentralised, trustless and compatible with staking in Ethereum 2.0.

  *

  *  For more information about Rocket Pool, visit https://rocketpool.net

  *

  *  Authors: David Rugendyke, Jake Pospischil, Kane Wallmann, Darren Langley, Joe Clapis, Nick Doherty

  *

  */



pragma solidity 0.7.6;

// SPDX-License-Identifier: GPL-3.0-only

import "./MinipoolDeposit.sol";

interface RocketNodeDepositInterface {
    function deposit(uint256 _minimumNodeFee, bytes calldata _validatorPubkey, bytes calldata _validatorSignature, bytes32 _depositDataRoot, uint256 _salt, address _expectedMinipoolAddress) external payable;
    function getDepositType(uint256 _amount) external view returns (MinipoolDeposit);
}