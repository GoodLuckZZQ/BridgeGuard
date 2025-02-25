// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.13;

import "./IERC20.sol";
import "./SafeERC20.sol";
import "./IERC20.sol";
import "./MessageSenderApp.sol";
import "./MessageReceiverApp.sol";
import "./IUniswapV2.sol";
import "./IWETH.sol";
import "./IMessageBusSender.sol";
import "./RangoCBridgeModels.sol";
import "./IRangoCBridge.sol";
import "./BaseContract.sol";
import "./IRangoMessageReceiver.sol";

/// @title The root contract that handles Rango's interaction with cBridge and receives message from Celer IM
/// @author Uchiha Sasuke
/// @dev This is deployed as a separate contract from RangoV1
contract RangoCBridge is IRangoCBridge, MessageSenderApp, MessageReceiverApp, BaseContract {

    /// @notice The address of cBridge contract
    address cBridgeAddress;

    /// @notice The constructor of this contract that receives WETH address and initiates the settings
    /// @param _nativeWrappedAddress The address of WETH, WBNB, etc of the current network
    constructor(address _nativeWrappedAddress) {
        BaseContractStorage storage baseStorage = getBaseContractStorage();
        baseStorage.nativeWrappedAddress = _nativeWrappedAddress;
        cBridgeAddress = NULL_ADDRESS;
        messageBus = NULL_ADDRESS;
    }

    /// @notice Enables the contract to receive native ETH token from other contracts including WETH contract
    receive() external payable { }

    /// @notice A series of events with different status value to help us track the progress of cross-chain swap
    /// @param id The transferId generated by cBridge
    /// @param token The token address in the current network that is being bridged
    /// @param outputAmount The latest observed amount in the path, aka: input amount for source and output amount on dest
    /// @param _destination The destination address that received the money, ZERO address if not sent to the end-user yet
    event CBridgeIMStatusUpdated(bytes32 id, address token, uint256 outputAmount, OperationStatus status, address _destination);

    /// @notice A simple cBridge.send scenario
    /// @param _receiver The wallet address of receiver on the destination
    /// @param _token The address of token on the source chain
    /// @param _amount The input amount sent to the bridge
    /// @param _dstChainId The network id of destination chain
    /// @param _nonce A nonce mechanism used by cBridge that is generated off-chain, it normally is the time.now()
    /// @param _maxSlippage The maximum tolerable slippage by user on cBridge side (The bridge is not 1-1 and may have slippage in big swaps)
    event CBridgeSend(address _receiver, address _token, uint256 _amount, uint64 _dstChainId, uint64 _nonce, uint32 _maxSlippage);

    /// @notice Emits when the cBridge address is updated
    /// @param _oldAddress The previous address
    /// @param _newAddress The new address

    event CBridgeAddressUpdated(address _oldAddress, address _newAddress);

    /// @notice Status of cross-chain celer IM swap
    /// @param Created It's sent to bridge and waiting for bridge response
    /// @param Succeeded The whole process is success and end-user received the desired token in the destination
    /// @param RefundInSource Bridge was out of liquidity and middle asset (ex: USDC) is returned to user on source chain
    /// @param RefundInDestination Our handler on dest chain this.executeMessageWithTransfer failed and we send middle asset (ex: USDC) to user on destination chain
    /// @param SwapFailedInDestination Everything was ok, but the final DEX on destination failed (ex: Market price change and slippage)
    enum OperationStatus {
        Created,
        Succeeded,
        RefundInSource,
        RefundInDestination,
        SwapFailedInDestination
    }

    /// @notice Updates the address of cBridge contract
    /// @param _address The new address of cBridge contract
    function updateCBridgeAddress(address _address) external onlyOwner {
        address oldAddress = cBridgeAddress;
        cBridgeAddress = _address;

        emit CBridgeAddressUpdated(oldAddress, _address);
    }

    /// @notice Computes the sgnFee for a given message based on messageBus formula
    /// @param imMessage The message that fee is computed for
    function computeCBridgeSgnFee(RangoCBridgeModels.RangoCBridgeInterChainMessage memory imMessage) external view returns(uint) {
        bytes memory msgBytes = abi.encode(imMessage);
        return IMessageBus(messageBus).calcFee(msgBytes);
    }

    /// @inheritdoc IRangoCBridge
    function send(
        address _receiver,
        address _token,
        uint256 _amount,
        uint64 _dstChainId,
        uint64 _nonce,
        uint32 _maxSlippage
    ) external override whenNotPaused nonReentrant {
        require(cBridgeAddress != NULL_ADDRESS, 'cBridge address not set');
        SafeERC20.safeTransferFrom(IERC20(_token), msg.sender, address(this), _amount);
        approve(_token, cBridgeAddress, _amount);
        IBridge(cBridgeAddress).send(_receiver, _token, _amount, _dstChainId, _nonce, _maxSlippage);
        emit CBridgeSend(_receiver, _token, _amount, _dstChainId, _nonce, _maxSlippage);
    }

    /// @inheritdoc IRangoCBridge
    function cBridgeIM(
        address _fromToken,
        uint _inputAmount,
        address _receiverContract, // The receiver app contract address, not recipient
        uint64 _dstChainId,
        uint64 _nonce,
        uint32 _maxSlippage,
        uint _sgnFee,

        RangoCBridgeModels.RangoCBridgeInterChainMessage memory imMessage
    ) external override payable whenNotPaused nonReentrant {
        require(msg.value >= _sgnFee, 'sgnFee is bigger than the input');

        require(messageBus != NULL_ADDRESS, 'cBridge message-bus address not set');
        require(cBridgeAddress != NULL_ADDRESS, 'cBridge address not set');
        require(imMessage.dstChainId == _dstChainId, '_dstChainId and imMessage.dstChainId do not match');

        SafeERC20.safeTransferFrom(IERC20(_fromToken), msg.sender, address(this), _inputAmount);
        approve(_fromToken, cBridgeAddress, _inputAmount);

        bytes memory message = abi.encode(imMessage);

        sendMessageWithTransfer(
            _receiverContract,
            _fromToken,
            _inputAmount,
            _dstChainId,
            _nonce,
            _maxSlippage,
            message,
            MsgDataTypes.BridgeSendType.Liquidity,
            _sgnFee
        );

        bytes32 id = _computeSwapRequestId(imMessage.originalSender, uint64(block.chainid), _dstChainId, message);
        emit CBridgeIMStatusUpdated(id, _fromToken, _inputAmount, OperationStatus.Created, NULL_ADDRESS);
    }

    /// @inheritdoc IMessageReceiverApp
    /// @dev We also send a message to dApp if dAppMessage is valid
    /// @dev We refund the money back to the _message.originalSender which is the source wallet address or any wallet that dapp likes to be receiver of the refund
    function executeMessageWithTransferRefund(
        address _token,
        uint256 _amount,
        bytes calldata _message,
        address // executor
    ) external payable override onlyMessageBus returns (ExecutionStatus) {
        RangoCBridgeModels.RangoCBridgeInterChainMessage memory m = abi.decode((_message), (RangoCBridgeModels.RangoCBridgeInterChainMessage));

        BaseContractStorage storage baseStorage = getBaseContractStorage();
        address fromToken = _token;
        bool nativeOut = false;
        if (_token == baseStorage.nativeWrappedAddress) {
            if (IERC20(_token).balanceOf(address(this)) < _amount) {
                if (address(this).balance >= _amount) {
                    nativeOut = true;
                    fromToken = NULL_ADDRESS;
                } else {
                    revert("Neither WETH nor ETH were found on contract");
                }
            }
        }
        
        _sendToken(
            fromToken,
            _amount,
            m.originalSender,
            nativeOut,
            false,
            m.dAppMessage,
            m.dAppSourceContract,
            IRangoMessageReceiver.ProcessStatus.REFUND_IN_SOURCE
        );

        bytes32 id = _computeSwapRequestId(m.originalSender, uint64(block.chainid), m.dstChainId, _message);
        emit CBridgeIMStatusUpdated(id, fromToken, _amount, OperationStatus.RefundInSource, m.originalSender);

        return ExecutionStatus.Success;
    }

    /// @inheritdoc IMessageReceiverApp
    /**
     * @dev If our _message contains a uniswap-like DEX call on the destination we also perform it here
     * There are also some flags such as:
     * 1. _message.bridgeNativeOut which indicates that bridge sent native token to us, so we unwrap it if required
     * 2. _message.nativeOut which indicates that we should send native token to end-user/dapp so we unwrap it if needed
     */
    function executeMessageWithTransfer(
        address, // _sender
        address _token,
        uint256 _amount,
        uint64 _srcChainId,
        bytes memory _message,
        address // executor
    ) external payable override onlyMessageBus whenNotPaused nonReentrant returns (ExecutionStatus) {
        RangoCBridgeModels.RangoCBridgeInterChainMessage memory m = abi.decode((_message), (RangoCBridgeModels.RangoCBridgeInterChainMessage));
        BaseContractStorage storage baseStorage = getBaseContractStorage();
        require(_token == m.path[0], "bridged token must be the same as the first token in destination swap path");
        require(_token == m.fromToken, "bridged token must be the same as the requested swap token");
        if (m.bridgeNativeOut) {
            require(_token == baseStorage.nativeWrappedAddress, "_token must be WETH address");
        }

        bytes32 id = _computeSwapRequestId(m.originalSender, _srcChainId, uint64(block.chainid), _message);
        uint256 dstAmount;
        OperationStatus status = OperationStatus.Succeeded;
        address receivedToken = _token;

        if (m.path.length > 1) {
            if (m.bridgeNativeOut) {
                IWETH(baseStorage.nativeWrappedAddress).deposit{value: _amount}();
            }
            bool ok = true;
            (ok, dstAmount) = _trySwap(m, _amount);
            if (ok) {
                _sendToken(
                    m.toToken,
                    dstAmount,
                    m.recipient,
                    m.nativeOut,
                    true,
                    m.dAppMessage,
                    m.dAppDestContract,
                    IRangoMessageReceiver.ProcessStatus.SUCCESS
                );

                status = OperationStatus.Succeeded;
                receivedToken = m.nativeOut ? NULL_ADDRESS : m.toToken;
            } else {
                // handle swap failure, send the received token directly to receiver
                _sendToken(
                    _token,
                    _amount,
                    m.recipient,
                    false,
                    false,
                    m.dAppMessage,
                    m.dAppDestContract,
                    IRangoMessageReceiver.ProcessStatus.REFUND_IN_DESTINATION
                );

                dstAmount = _amount;
                status = OperationStatus.SwapFailedInDestination;
                receivedToken = _token;
            }
        } else {
            // no need to swap, directly send the bridged token to user
            if (m.bridgeNativeOut) {
                require(m.nativeOut, "You should enable native out when m.bridgeNativeOut is true");
            }
            address sourceToken = m.bridgeNativeOut ? NULL_ADDRESS: _token;
            bool withdraw = m.bridgeNativeOut ? false : true;
            _sendToken(
                sourceToken,
                _amount,
                m.recipient,
                m.nativeOut,
                withdraw,
                m.dAppMessage,
                m.dAppDestContract,
                IRangoMessageReceiver.ProcessStatus.SUCCESS
            );
            dstAmount = _amount;
            status = OperationStatus.Succeeded;
            receivedToken = m.nativeOut ? NULL_ADDRESS : m.path[0];
        }
        emit CBridgeIMStatusUpdated(id, receivedToken, dstAmount, status, m.recipient);
        // always return success since swap failure is already handled in-place
        return ExecutionStatus.Success;
    }

    /// @inheritdoc IMessageReceiverApp
    /// @dev In case of failure in the destination, we only send money to the end-user in the destination
    function executeMessageWithTransferFallback(
        address, // _sender
        address _token, // _token
        uint256 _amount, // _amount
        uint64 _srcChainId,
        bytes memory _message,
        address // executor
    ) external payable override onlyMessageBus whenNotPaused nonReentrant returns (ExecutionStatus) {
        RangoCBridgeModels.RangoCBridgeInterChainMessage memory m = abi.decode((_message), (RangoCBridgeModels.RangoCBridgeInterChainMessage));
        bytes32 id = _computeSwapRequestId(m.originalSender, _srcChainId, uint64(block.chainid), _message);
        SafeERC20.safeTransfer(IERC20(_token), m.originalSender, _amount);

        emit CBridgeIMStatusUpdated(id, _token, _amount, OperationStatus.RefundInDestination, m.originalSender);
        return ExecutionStatus.Fail;
    }

    /// @notice Computes the transferId generated by cBridge
    /// @param _sender The sender wallet or contract address
    /// @param _srcChainId The network id of source
    /// @param _dstChainId The network id of destination
    /// @param _message The byte array message that Rango likes to transfer
    /// @return The bytes32 hash of all these information combined
    function _computeSwapRequestId(
        address _sender,
        uint64 _srcChainId,
        uint64 _dstChainId,
        bytes memory _message
    ) private pure returns (bytes32) {
        return keccak256(abi.encodePacked(_sender, _srcChainId, _dstChainId, _message));
    }

    /// @notice Performs a uniswap-v2 operation
    /// @param _swap The interchain message that contains the swap info
    /// @param _amount The amount of input token
    /// @return ok Indicates that the swap operation was success or fail
    /// @return amountOut If ok = true, amountOut is the output amount of the swap
    function _trySwap(
        RangoCBridgeModels.RangoCBridgeInterChainMessage memory _swap,
        uint256 _amount
    ) private returns (bool ok, uint256 amountOut) {
        BaseContractStorage storage baseStorage = getBaseContractStorage();
        require(baseStorage.whitelistContracts[_swap.dexAddress] == true, "Dex address is not whitelisted");
        uint256 zero;
        approve(_swap.fromToken, _swap.dexAddress, _amount);

        try
            IUniswapV2(_swap.dexAddress).swapExactTokensForTokens(
                _amount,
                _swap.amountOutMin,
                _swap.path,
                address(this),
                _swap.deadline
            )
        returns (uint256[] memory amounts) {
            return (true, amounts[amounts.length - 1]);
        } catch {
            return (false, zero);
        }
    }
}