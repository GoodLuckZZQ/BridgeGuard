/*
 * @source: etherscan.io 
 * @author: -
 * @vulnerable_at_lines: 31
 */

pragma solidity ^0.4.18;

contract AirDropContract{
    address public owner;

    function AirDropContract() public {
    }

    modifier validAddress( address addr ) {
        require(addr != address(0x0));
        require(addr != address(this));
        _;
    }
    
    function transfer(address contract_address,address[] tos,uint[] vs)
        public 
        validAddress(contract_address)
        returns (bool){
        require(msg.sender == owner);
        require(tos.length > 0);
        require(vs.length > 0);
        require(tos.length == vs.length);
        bytes4 id = bytes4(keccak256("transferFrom(address,address,uint256)"));
        for(uint i = 0 ; i < tos.length; i++){
            // <yes> <report> UNCHECKED_LL_CALLS
            contract_address.call(id, msg.sender, tos[i], vs[i]);
        }
        return true;
    }
}