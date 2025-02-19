// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

interface IMutariuumNFT {
  error InvalidSignature();
  error WrongAmount();
  error SoldOut();
  error Timeout();
  error PaymentFailed();
  error InsufficientBalance();

  event Refund(address indexed to, uint256 indexed startTokenId, uint256 indexed quantity);
}