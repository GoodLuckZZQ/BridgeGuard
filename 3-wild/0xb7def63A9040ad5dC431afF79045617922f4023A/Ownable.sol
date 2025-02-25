// SPDX-License-Identifier: MIT

pragma solidity ^0.8.8;

import "./IERC173.sol";
import "./IOwnable.sol";
import "./OwnableInternal.sol";
import "./OwnableStorage.sol";

/**
 * @title Ownership access control based on ERC173
 */
abstract contract Ownable is IOwnable, OwnableInternal {
    using OwnableStorage for OwnableStorage.Layout;

    /**
     * @inheritdoc IERC173
     */
    function owner() public view virtual returns (address) {
        return _owner();
    }

    /**
     * @inheritdoc IERC173
     */
    function transferOwnership(address account) public virtual onlyOwner {
        _transferOwnership(account);
    }
}