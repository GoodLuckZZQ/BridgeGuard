// SPDX-License-Identifier: AGPL-3.0
pragma solidity 0.8.10;

import "./InitializableUpgradeabilityProxy.sol";
import "./Proxy.sol";
import "./BaseImmutableAdminUpgradeabilityProxy.sol";

/**
 * @title InitializableAdminUpgradeabilityProxy
 *
 * @dev Extends BaseAdminUpgradeabilityProxy with an initializer function
 */
contract InitializableImmutableAdminUpgradeabilityProxy is
    BaseImmutableAdminUpgradeabilityProxy,
    InitializableUpgradeabilityProxy
{
    /**
     * @dev Constructor.
     * @param admin The address of the admin
     */
    constructor(address admin) BaseImmutableAdminUpgradeabilityProxy(admin) {
        // Intentionally left blank
    }

    /// @inheritdoc BaseImmutableAdminUpgradeabilityProxy
    function _willFallback()
        internal
        override(BaseImmutableAdminUpgradeabilityProxy, Proxy)
    {
        BaseImmutableAdminUpgradeabilityProxy._willFallback();
    }
}