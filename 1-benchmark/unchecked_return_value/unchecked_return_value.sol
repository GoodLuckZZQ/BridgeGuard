/*
 * @source: https://smartcontractsecurity.github.io/SWC-registry/docs/SWC-104#unchecked-return-valuesol
 * @author: -
 * @vulnerable_at_lines: 17
 */

pragma solidity 0.4.25;

contract ReturnValue {

  address public owner;
  function callchecked(address callee) public {
    require(msg.sender == owner);
    require(callee.call());
  }

  function callnotchecked(address callee) public {
    require(msg.sender == owner);
     // <yes> <report> UNCHECKED_LL_CALLS
    callee.call();
  }
}
