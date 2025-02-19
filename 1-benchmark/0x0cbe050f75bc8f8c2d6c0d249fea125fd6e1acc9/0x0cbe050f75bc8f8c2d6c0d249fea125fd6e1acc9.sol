/*
 * @source: etherscan.io 
 * @author: -
 * @vulnerable_at_lines: 12
 */

pragma solidity ^0.4.10;

contract Caller {
    address public owner;
    function callAddress(address a) {
        require(msg.sender == owner);
        // <yes> <report> UNCHECKED_LL_CALLS
        a.call();
    }
}