// SPDX-License-Identifier: MIT
pragma solidity 0.8.10;

import "./SafeTransferLib.sol";
import "./ReentrancyGuard.sol";
import "./Owners.sol";
import "./TSAggregatorTokenTransferProxy.sol";

abstract contract TSAggregator is Owners, ReentrancyGuard {
    using SafeTransferLib for address;

    event FeeSet(uint256 fee, address feeRecipient);

    uint256 public fee;
    address public feeRecipient;
    TSAggregatorTokenTransferProxy public tokenTransferProxy;

    constructor(address _tokenTransferProxy) {
        _setOwner(msg.sender, true);
        tokenTransferProxy = TSAggregatorTokenTransferProxy(_tokenTransferProxy);
    }

    // Needed for the swap router to be able to send back ETH
    receive() external payable {}

    function setFee(uint256 _fee, address _feeRecipient) external isOwner {
        require(_fee <= 1000, "fee can not be more than 10%");
        fee = _fee;
        feeRecipient = _feeRecipient;
        emit FeeSet(_fee, _feeRecipient);
    }

    function skimFee(uint256 amount) internal returns (uint256) {
        if (fee != 0 && feeRecipient != address(0)) {
            uint256 feeAmount = (amount * fee) / 10000;
            feeRecipient.safeTransferETH(feeAmount);
            amount -= feeAmount;
        }
        return amount;
    }

    // Parse amountOutMin treating the last 2 digits as an exponent
    // So 15e4 = 150000. This allows for compressed memos on chains
    // with limited space like Bitcoin
    function _parseAmountOutMin(uint256 amount) internal pure returns (uint256) {
      return amount / 100 * (10 ** (amount % 100));
    }
}