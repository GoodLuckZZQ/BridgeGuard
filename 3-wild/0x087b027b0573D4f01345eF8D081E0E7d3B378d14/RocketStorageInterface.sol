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



pragma solidity >0.5.0 <0.9.0;

// SPDX-License-Identifier: GPL-3.0-only

interface RocketStorageInterface {

    // Deploy status
    function getDeployedStatus() external view returns (bool);

    // Guardian
    function getGuardian() external view returns(address);
    function setGuardian(address _newAddress) external;
    function confirmGuardian() external;

    // Getters
    function getAddress(bytes32 _key) external view returns (address);
    function getUint(bytes32 _key) external view returns (uint);
    function getString(bytes32 _key) external view returns (string memory);
    function getBytes(bytes32 _key) external view returns (bytes memory);
    function getBool(bytes32 _key) external view returns (bool);
    function getInt(bytes32 _key) external view returns (int);
    function getBytes32(bytes32 _key) external view returns (bytes32);

    // Setters
    function setAddress(bytes32 _key, address _value) external;
    function setUint(bytes32 _key, uint _value) external;
    function setString(bytes32 _key, string calldata _value) external;
    function setBytes(bytes32 _key, bytes calldata _value) external;
    function setBool(bytes32 _key, bool _value) external;
    function setInt(bytes32 _key, int _value) external;
    function setBytes32(bytes32 _key, bytes32 _value) external;

    // Deleters
    function deleteAddress(bytes32 _key) external;
    function deleteUint(bytes32 _key) external;
    function deleteString(bytes32 _key) external;
    function deleteBytes(bytes32 _key) external;
    function deleteBool(bytes32 _key) external;
    function deleteInt(bytes32 _key) external;
    function deleteBytes32(bytes32 _key) external;

    // Arithmetic
    function addUint(bytes32 _key, uint256 _amount) external;
    function subUint(bytes32 _key, uint256 _amount) external;

    // Protected storage
    function getNodeWithdrawalAddress(address _nodeAddress) external view returns (address);
    function getNodePendingWithdrawalAddress(address _nodeAddress) external view returns (address);
    function setWithdrawalAddress(address _nodeAddress, address _newWithdrawalAddress, bool _confirm) external;
    function confirmWithdrawalAddress(address _nodeAddress) external;
}