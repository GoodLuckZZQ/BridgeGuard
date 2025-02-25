// SPDX-License-Identifier: AGPL-3.0
pragma solidity ^0.8.0;

import "./LSSVMPairERC20.sol";
import "./LSSVMPairMissingEnumerable.sol";
import "./ILSSVMPairFactoryLike.sol";

contract LSSVMPairMissingEnumerableERC20 is
    LSSVMPairMissingEnumerable,
    LSSVMPairERC20
{
    function pairVariant()
        public
        pure
        override
        returns (ILSSVMPairFactoryLike.PairVariant)
    {
        return ILSSVMPairFactoryLike.PairVariant.MISSING_ENUMERABLE_ERC20;
    }
}