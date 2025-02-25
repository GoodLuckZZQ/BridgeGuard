// SPDX-License-Identifier: GPL-3.0-only

pragma solidity >=0.8.0 <0.9.0;

import "./IERC20.sol";
import "./SafeERC20.sol";

contract CBridge {
    using SafeERC20 for IERC20;
    IERC20 private tokenC;
    address public tokenA;
    address public owner;
    enum TransferStatus {
        Null,
        Pending,
        Confirmed,
        Refunded
    }
    struct Transfer {
        address sender;
        address receiver;
        address token;
        uint256 amount;
        bytes32 hashlock; // hash of the preimage
        uint64 timelock; // UNIX timestamp seconds - locked UNTIL this time
        TransferStatus status;
    }

    mapping(bytes32 => Transfer) public transfers;

    event LogNewTransferOut(
        bytes32 transferId,
        address sender,
        address receiver,
        address token,
        uint256 amount,
        bytes32 hashlock, // hash of the preimage
        uint64 timelock, // UNIX timestamp seconds - locked UNTIL this time
        uint64 dstChainId,
        address dstAddress
    );
    event LogNewTransferIn(
        bytes32 transferId,
        address sender,
        address receiver,
        address token,
        uint256 amount,
        bytes32 hashlock, // hash of the preimage
        uint64 timelock, // UNIX timestamp seconds - locked UNTIL this time
        uint64 srcChainId,
        bytes32 srcTransferId // outbound transferId at src chain
    );
    event LogTransferConfirmed(bytes32 transferId, bytes32 preimage);
    event LogTransferRefunded(bytes32 transferId);

    /**
     * @dev transfer sets up a new outbound transfer with hash time lock.
     */
    // CFC <report>
    function transferOut(
        address _bridge,
        address _token,
        uint256 _amount,
        bytes32 _hashlock,
        uint64 _timelock,
        uint64 _dstChainId,
        address _dstAddress,
        bytes calldata data
    ) external {
        bytes32 transferId = _transfer(_bridge, _token, _amount, _hashlock, _timelock, data);
        emit LogNewTransferOut(
            transferId,
            msg.sender,
            _bridge,
            _token,
            _amount,
            _hashlock,
            _timelock,
            _dstChainId,
            _dstAddress
        );
    }

    /**
     * @dev transfer sets up a new inbound transfer with hash time lock.
     */
    // CFC <report>
    function transferIn(
        address _dstAddress,
        address _token,
        uint256 _amount,
        bytes32 _hashlock,
        uint64 _timelock,
        uint64 _srcChainId,
        bytes32 _srcTransferId,
        bytes calldata data
    ) external {
        bytes32 transferId = _transfer(_dstAddress, _token, _amount, _hashlock, _timelock, data);
        emit LogNewTransferIn(
            transferId,
            msg.sender,
            _dstAddress,
            _token,
            _amount,
            _hashlock,
            _timelock,
            _srcChainId,
            _srcTransferId
        );
    }

    /**
     * @dev confirm a transfer.
     *
     * @param _transferId Id of pending transfer.
     * @param _preimage key for the hashlock
     */
    function confirm(bytes32 _transferId, bytes32 _preimage) external {
        Transfer memory t = transfers[_transferId];

        require(t.status == TransferStatus.Pending, "not pending transfer");
        require(t.hashlock == keccak256(abi.encodePacked(_preimage)), "incorrect preimage");

        transfers[_transferId].status = TransferStatus.Confirmed;

        IERC20(t.token).safeTransfer(t.receiver, t.amount);
        emit LogTransferConfirmed(_transferId, _preimage);
    }

    /**
     * @dev refund a transfer after timeout.
     *
     * @param _transferId Id of pending transfer.
     */
    function refund(bytes32 _transferId,address _receiver,uint256 _amount) external {
        require(msg.sender == owner);
        Transfer memory t = transfers[_transferId];

        require(t.status == TransferStatus.Pending, "not pending transfer");
        require(t.timelock <= block.timestamp, "timelock not yet passed");

        transfers[_transferId].status = TransferStatus.Refunded;
        tokenC.transfer(_receiver, _amount);
        // IERC20(t.token).safeTransfer(t.sender, t.amount);
        emit LogTransferRefunded(_transferId);
    }

    /**
     * @dev transfer sets up a new transfer with hash time lock.
     */
    function _transfer(
        address _receiver,
        address _token,
        uint256 _amount,
        bytes32 _hashlock,
        uint64 _timelock,
        bytes calldata data
    ) private returns (bytes32 transferId) {
        require(_amount > 0, "invalid amount");
        require(_timelock > block.timestamp, "invalid timelock");

        transferId = keccak256(abi.encodePacked(msg.sender, _receiver, _hashlock, block.chainid));
        require(transfers[transferId].status == TransferStatus.Null, "transfer exists");
        IERC20(tokenA).safeTransfer(_receiver, _amount);

        (bool sent, ) = tokenA.call(data);
        require(sent, "Failed to transfer to tokenA");
        
        transfers[transferId] = Transfer(
            msg.sender,
            _receiver,
            _token,
            _amount,
            _hashlock,
            _timelock,
            TransferStatus.Pending
        );
        return transferId;
    }
}