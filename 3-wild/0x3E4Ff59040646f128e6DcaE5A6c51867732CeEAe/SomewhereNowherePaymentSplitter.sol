// SPDX-License-Identifier: MIT

pragma solidity ^0.8.4;

import "./PaymentSplitter.sol";

contract SomewhereNowherePaymentSplitter is PaymentSplitter {
    constructor(address[] memory payees, uint256[] memory shares)
        PaymentSplitter(payees, shares)
    {}
}