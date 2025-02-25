// SPDX-License-Identifier: GPL-3.0-only
pragma solidity 0.7.6;

import "./ERC721.sol";
import "./Clones.sol";
import "./IFactory.sol";
import "./InstanceRegistry.sol";
import "./UniversalVault.sol";
import "./ProxyFactory.sol";

/// @title Vault Factory
/// @dev Security contact: [email protected]
contract VaultFactory is IFactory, IInstanceRegistry, ERC721 {
    address private immutable _template;

    constructor(address template) ERC721("Universal Vault v1", "VAULT-v1") {
        require(template != address(0), "VaultFactory: invalid template");
        _template = template;
    }

    /* registry functions */

    function isInstance(address instance) external view override returns (bool validity) {
        return ERC721._exists(uint256(instance));
    }

    function instanceCount() external view override returns (uint256 count) {
        return ERC721.totalSupply();
    }

    function instanceAt(uint256 index) external view override returns (address instance) {
        return address(ERC721.tokenByIndex(index));
    }

    /* factory functions */

    function create(bytes calldata) external override returns (address vault) {
        return create();
    }

    function create2(bytes calldata, bytes32 salt) external override returns (address vault) {
        return create2(salt);
    }

    function create() public returns (address vault) {
        // create clone and initialize
        vault = ProxyFactory._create(_template, abi.encodeWithSelector(IUniversalVault.initialize.selector));

        // mint nft to caller
        ERC721._safeMint(msg.sender, uint256(vault));

        // emit event
        emit InstanceAdded(vault);

        // explicit return
        return vault;
    }

    function create2(bytes32 salt) public returns (address vault) {
        // create clone and initialize
        vault = ProxyFactory._create2(_template, abi.encodeWithSelector(IUniversalVault.initialize.selector), salt);

        // mint nft to caller
        ERC721._safeMint(msg.sender, uint256(vault));

        // emit event
        emit InstanceAdded(vault);

        // explicit return
        return vault;
    }

    /* getter functions */

    function getTemplate() external view returns (address template) {
        return _template;
    }

    function predictCreate2Address(bytes32 salt) external view returns (address instance) {
        return Clones.predictDeterministicAddress(_template, salt, address(this));
    }

    function addressToUint(address vault) external pure returns (uint256 tokenId) {
        return uint256(vault);
    }

    function uint256ToAddress(uint256 tokenId) external pure returns (address vault) {
        return address(tokenId);
    }
}