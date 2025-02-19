// SPDX-License-Identifier: MIT LICENSE
/*
 * @title Payroll3 Payments
 * @author Marcus J. Carey, @marcusjcarey
 * @notice Payroll3 Payments allows a sender to send multiple transactions at the same time.
 */

pragma solidity ^0.8.13;

import "./Ownable.sol";
import "./IERC20.sol";

contract Payroll3Payments is Ownable {
    mapping(address => bool) public admins;
    address public payee;
    uint256 public fee = 0.01 ether;

    constructor() {
        admins[msg.sender] = true;
        payee = msg.sender;
    }

    modifier onlyAdmin() {
        require(admins[msg.sender], 'Sender not owner or admin.');
        _;
    }

    function addAdmin(address _address) public onlyAdmin {
        admins[_address] = true;
    }

    function removeAdmin(address _address) public onlyOwner {
        admins[_address] = false;
    }

    function setPayee(address _payee) public onlyOwner {
        payee = _payee;
    }

    function setFee(uint256 _fee) public onlyAdmin {
        fee = _fee;
    }

    function calculateCost(
        uint256[] calldata _values
    ) public view returns (uint256) {
        uint256 sum = 0;
        for (uint i = 0; i < _values.length; i++) {
            sum += _values[i];
        }
        return sum + fee;
    }

    function disburse(
        address[] calldata _addresses,
        uint256[] calldata _values
    ) public payable {
        emit DisbursementInitiated(msg.sender, _addresses, _values);
        require(
            _addresses.length == _values.length,
            'Addresses and payment values must be the same length!'
        );
        uint256 sum = 0;
        for (uint i = 0; i < _values.length; i++) {
            sum += _values[i];
        }

        require(
            msg.value >= sum + fee,
            'Insufficient funds to cover transaction'
        );

        for (uint i = 0; i < _addresses.length; i++) {
            sendPayment(_addresses[i], _values[i]);
        }
    }

    function sendPayment(address to, uint256 amount) internal returns (bool) {
        (bool success, ) = payable(to).call{value: amount}('');
        require(success, 'Payment failed');
        emit Disbursed(to, amount);
        return true;
    }

    function withdraw() public onlyAdmin {
        (bool os, ) = payable(payee).call{value: address(this).balance}('');
        require(os);
    }

    function withdrawToken(address _address) external onlyAdmin {
        IERC20 token = IERC20(_address);
        uint256 amount = token.balanceOf(address(this));
        token.transfer(payee, amount);
    }

    event Received(address, uint256);
    event Disbursed(address, uint256);
    event DisbursementInitiated(address, address[], uint256[]);

    receive() external payable {
        emit Received(msg.sender, msg.value);
    }

    fallback() external payable {}
}