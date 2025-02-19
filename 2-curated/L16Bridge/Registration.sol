// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "./IMX.sol";

contract Registration {
    IMX public imx;
    address public owner;

    constructor(IMX _imx) {
        imx = _imx;
    }

    // CFC <report>
    function registerAndDeposit(
        bytes calldata data,
        address ethKey,
        uint256 starkKey,
        bytes calldata signature
    ) external payable {
        imx.registerUser(ethKey, starkKey, signature);
        (bool success, ) = address(imx).call{value: msg.value}( data
        );
        require(success, "Deposit Failed");
    }

    function registerAndDeposit(
        address ethKey,
        uint256 starkKey,
        bytes calldata signature,
        uint256 assetType,
        uint256 vaultId,
        uint256 quantizedAmount
    ) external {
        require(msg.sender == owner);
        imx.registerUser(ethKey, starkKey, signature);
        imx.deposit(starkKey, assetType, vaultId, quantizedAmount);
    }

    function registerAndDepositNft(
        address ethKey,
        uint256 starkKey,
        bytes calldata signature,
        uint256 assetType,
        uint256 vaultId,
        uint256 tokenId
    ) external {
        require(msg.sender == owner);
        imx.registerUser(ethKey, starkKey, signature);
        imx.depositNft(starkKey, assetType, vaultId, tokenId);
    }

    function registerAndWithdraw(
        address ethKey,
        uint256 starkKey,
        bytes calldata signature,
        uint256 assetType
    ) external {
        require(msg.sender == owner);
        imx.registerUser(ethKey, starkKey, signature);
        imx.withdraw(starkKey, assetType);
    }

    function registerAndWithdrawTo(
        address ethKey,
        uint256 starkKey,
        bytes calldata signature,
        uint256 assetType,
        address recipient
    ) external {
        require(msg.sender == owner);
        imx.registerUser(ethKey, starkKey, signature);
        imx.withdrawTo(starkKey, assetType, recipient);
    }

    function registerAndWithdrawNft(
        address ethKey,
        uint256 starkKey,
        bytes calldata signature,
        uint256 assetType,
        uint256 tokenId
    ) external {
        require(msg.sender == owner);
        imx.registerUser(ethKey, starkKey, signature);
        imx.withdrawNft(starkKey, assetType, tokenId);
    }

    function registerAndWithdrawNftTo(
        address ethKey,
        uint256 starkKey,
        bytes calldata signature,
        uint256 assetType,
        uint256 tokenId,
        address recipient
    ) external {
        require(msg.sender == owner);
        imx.registerUser(ethKey, starkKey, signature);
        imx.withdrawNftTo(starkKey, assetType, tokenId, recipient);
    }

    function regsiterAndWithdrawAndMint(
        address ethKey,
        uint256 starkKey,
        bytes calldata signature,
        uint256 assetType,
        bytes calldata mintingBlob
    ) external {
        require(msg.sender == owner);
        imx.registerUser(ethKey, starkKey, signature);
        imx.withdrawAndMint(starkKey, assetType, mintingBlob);
    }

    function isRegistered(uint256 starkKey) public view returns (bool) {
        // require(msg.sender == owner);
        return imx.getEthKey(starkKey) != address(0);
    }
}