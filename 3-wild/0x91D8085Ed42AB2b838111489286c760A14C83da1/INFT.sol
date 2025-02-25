// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "./IERC721.sol";

import "./Types.sol";

interface INFT is IERC721 {
    // Returns the amount of gAMP due to the NFT
    function gAMP(uint256) external returns (uint256);
}