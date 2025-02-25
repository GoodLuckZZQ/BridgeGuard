/*

  Copyright 2020 ZeroEx Intl.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

*/

pragma solidity ^0.6.5;
pragma experimental ABIEncoderV2;

import "./LibRichErrorsV06.sol";
import "./LibBytesV06.sol";
import "./LibMetaTransactionsRichErrors.sol";
import "./FixinCommon.sol";
import "./FixinEIP712.sol";
import "./LibMigrate.sol";
import "./LibMetaTransactionsStorage.sol";
import "./IMetaTransactions.sol";
import "./ITransformERC20.sol";
import "./ISignatureValidator.sol";
import "./ITokenSpender.sol";
import "./IFeature.sol";


/// @dev MetaTransactions feature.
contract MetaTransactions is
    IFeature,
    IMetaTransactions,
    FixinCommon,
    FixinEIP712
{
    using LibBytesV06 for bytes;
    using LibRichErrorsV06 for bytes;

    /// @dev Intermediate state vars to avoid stack overflows.
    struct ExecuteState {
        address sender;
        bytes32 hash;
        MetaTransactionData mtx;
        bytes signature;
        bytes4 selector;
        uint256 selfBalance;
        uint256 executedBlockNumber;
    }

    struct TransformERC20Args {
        IERC20TokenV06 inputToken;
        IERC20TokenV06 outputToken;
        uint256 inputTokenAmount;
        uint256 minOutputTokenAmount;
        ITransformERC20.Transformation[] transformations;
    }

    /// @dev Name of this feature.
    string public constant override FEATURE_NAME = "MetaTransactions";
    /// @dev Version of this feature.
    uint256 public immutable override FEATURE_VERSION = _encodeVersion(1, 0, 0);
    /// @dev EIP712 typehash of the `MetaTransactionData` struct.
    bytes32 public immutable MTX_EIP712_TYPEHASH = keccak256(
        "MetaTransactionData("
            "address signer,"
            "address sender,"
            "uint256 minGasPrice,"
            "uint256 maxGasPrice,"
            "uint256 expirationTime,"
            "uint256 salt,"
            "bytes callData,"
            "uint256 value,"
            "address feeToken,"
            "uint256 feeAmount"
        ")"
    );

    constructor(address zeroExAddress)
        public
        FixinCommon()
        FixinEIP712(zeroExAddress)
    {
        // solhint-disable-next-line no-empty-blocks
    }

    /// @dev Initialize and register this feature.
    ///      Should be delegatecalled by `Migrate.migrate()`.
    /// @return success `LibMigrate.SUCCESS` on success.
    function migrate()
        external
        returns (bytes4 success)
    {
        _registerFeatureFunction(this.executeMetaTransaction.selector);
        _registerFeatureFunction(this.executeMetaTransactions.selector);
        _registerFeatureFunction(this._executeMetaTransaction.selector);
        _registerFeatureFunction(this.getMetaTransactionExecutedBlock.selector);
        _registerFeatureFunction(this.getMetaTransactionHashExecutedBlock.selector);
        _registerFeatureFunction(this.getMetaTransactionHash.selector);
        return LibMigrate.MIGRATE_SUCCESS;
    }

    /// @dev Execute a single meta-transaction.
    /// @param mtx The meta-transaction.
    /// @param signature The signature by `mtx.signer`.
    /// @return returnData The ABI-encoded result of the underlying call.
    function executeMetaTransaction(
        MetaTransactionData memory mtx,
        bytes memory signature
    )
        public
        payable
        override
        returns (bytes memory returnData)
    {
        return _executeMetaTransactionPrivate(
            msg.sender,
            mtx,
            signature
        );
    }

    /// @dev Execute multiple meta-transactions.
    /// @param mtxs The meta-transactions.
    /// @param signatures The signature by each respective `mtx.signer`.
    /// @return returnDatas The ABI-encoded results of the underlying calls.
    function executeMetaTransactions(
        MetaTransactionData[] memory mtxs,
        bytes[] memory signatures
    )
        public
        payable
        override
        returns (bytes[] memory returnDatas)
    {
        if (mtxs.length != signatures.length) {
            LibMetaTransactionsRichErrors.InvalidMetaTransactionsArrayLengthsError(
                mtxs.length,
                signatures.length
            ).rrevert();
        }
        returnDatas = new bytes[](mtxs.length);
        for (uint256 i = 0; i < mtxs.length; ++i) {
            returnDatas[i] = _executeMetaTransactionPrivate(
                msg.sender,
                mtxs[i],
                signatures[i]
            );
        }
    }

    /// @dev Execute a meta-transaction via `sender`. Privileged variant.
    ///      Only callable from within.
    /// @param sender Who is executing the meta-transaction..
    /// @param mtx The meta-transaction.
    /// @param signature The signature by `mtx.signer`.
    /// @return returnData The ABI-encoded result of the underlying call.
    function _executeMetaTransaction(
        address sender,
        MetaTransactionData memory mtx,
        bytes memory signature
    )
        public
        payable
        override
        onlySelf
        returns (bytes memory returnData)
    {
        return _executeMetaTransactionPrivate(sender, mtx, signature);
    }

    /// @dev Get the block at which a meta-transaction has been executed.
    /// @param mtx The meta-transaction.
    /// @return blockNumber The block height when the meta-transactioin was executed.
    function getMetaTransactionExecutedBlock(MetaTransactionData memory mtx)
        public
        override
        view
        returns (uint256 blockNumber)
    {
        return getMetaTransactionHashExecutedBlock(getMetaTransactionHash(mtx));
    }

    /// @dev Get the block at which a meta-transaction hash has been executed.
    /// @param mtxHash The meta-transaction hash.
    /// @return blockNumber The block height when the meta-transactioin was executed.
    function getMetaTransactionHashExecutedBlock(bytes32 mtxHash)
        public
        override
        view
        returns (uint256 blockNumber)
    {
        return LibMetaTransactionsStorage.getStorage().mtxHashToExecutedBlockNumber[mtxHash];
    }

    /// @dev Get the EIP712 hash of a meta-transaction.
    /// @param mtx The meta-transaction.
    /// @return mtxHash The EIP712 hash of `mtx`.
    function getMetaTransactionHash(MetaTransactionData memory mtx)
        public
        override
        view
        returns (bytes32 mtxHash)
    {
        return _getEIP712Hash(keccak256(abi.encode(
            MTX_EIP712_TYPEHASH,
            mtx.signer,
            mtx.sender,
            mtx.minGasPrice,
            mtx.maxGasPrice,
            mtx.expirationTime,
            mtx.salt,
            keccak256(mtx.callData),
            mtx.value,
            mtx.feeToken,
            mtx.feeAmount
        )));
    }

    /// @dev Execute a meta-transaction by `sender`. Low-level, hidden variant.
    /// @param sender Who is executing the meta-transaction..
    /// @param mtx The meta-transaction.
    /// @param signature The signature by `mtx.signer`.
    /// @return returnData The ABI-encoded result of the underlying call.
    function _executeMetaTransactionPrivate(
        address sender,
        MetaTransactionData memory mtx,
        bytes memory signature
    )
        private
        returns (bytes memory returnData)
    {
        ExecuteState memory state;
        state.sender = sender;
        state.hash = getMetaTransactionHash(mtx);
        state.mtx = mtx;
        state.signature = signature;

        _validateMetaTransaction(state);

        // Mark the transaction executed.
        assert(block.number > 0);
        LibMetaTransactionsStorage.getStorage()
            .mtxHashToExecutedBlockNumber[state.hash] = block.number;

        // Execute the call based on the selector.
        state.selector = mtx.callData.readBytes4(0);
        if (state.selector == ITransformERC20.transformERC20.selector) {
            returnData = _executeTransformERC20Call(state);
        } else {
            LibMetaTransactionsRichErrors
                .MetaTransactionUnsupportedFunctionError(state.hash, state.selector)
                .rrevert();
        }
        // Pay the fee to the sender.
        if (mtx.feeAmount > 0) {
            ITokenSpender(address(this))._spendERC20Tokens(
                mtx.feeToken,
                mtx.signer, // From the signer.
                sender, // To the sender.
                mtx.feeAmount
            );
        }
        emit MetaTransactionExecuted(
            state.hash,
            state.selector,
            mtx.signer,
            mtx.sender
        );
    }

    /// @dev Validate that a meta-transaction is executable.
    function _validateMetaTransaction(ExecuteState memory state)
        private
        view
    {
        // Must be from the required sender, if set.
        if (state.mtx.sender != address(0) && state.mtx.sender != state.sender) {
            LibMetaTransactionsRichErrors
                .MetaTransactionWrongSenderError(
                    state.hash,
                    state.sender,
                    state.mtx.sender
                ).rrevert();
        }
        // Must not be expired.
        if (state.mtx.expirationTime <= block.timestamp) {
            LibMetaTransactionsRichErrors
                .MetaTransactionExpiredError(
                    state.hash,
                    block.timestamp,
                    state.mtx.expirationTime
                ).rrevert();
        }
        // Must have a valid gas price.
        if (state.mtx.minGasPrice > tx.gasprice || state.mtx.maxGasPrice < tx.gasprice) {
            LibMetaTransactionsRichErrors
                .MetaTransactionGasPriceError(
                    state.hash,
                    tx.gasprice,
                    state.mtx.minGasPrice,
                    state.mtx.maxGasPrice
                ).rrevert();
        }
        // Must have enough ETH.
        state.selfBalance  = address(this).balance;
        if (state.mtx.value > state.selfBalance) {
            LibMetaTransactionsRichErrors
                .MetaTransactionInsufficientEthError(
                    state.hash,
                    state.selfBalance,
                    state.mtx.value
                ).rrevert();
        }
        // Must be signed by signer.
        try
            ISignatureValidator(address(this))
                .validateHashSignature(state.hash, state.mtx.signer, state.signature)
        {}
        catch (bytes memory err) {
            LibMetaTransactionsRichErrors
                .MetaTransactionInvalidSignatureError(
                    state.hash,
                    state.signature,
                    err
                ).rrevert();
        }
        // Transaction must not have been already executed.
        state.executedBlockNumber = LibMetaTransactionsStorage
            .getStorage().mtxHashToExecutedBlockNumber[state.hash];
        if (state.executedBlockNumber != 0) {
            LibMetaTransactionsRichErrors
                .MetaTransactionAlreadyExecutedError(
                    state.hash,
                    state.executedBlockNumber
                ).rrevert();
        }
    }

    /// @dev Execute a `ITransformERC20.transformERC20()` meta-transaction call
    ///      by decoding the call args and translating the call to the internal
    ///      `ITransformERC20._transformERC20()` variant, where we can override
    ///      the taker address.
    function _executeTransformERC20Call(ExecuteState memory state)
        private
        returns (bytes memory returnData)
    {
        // HACK(dorothy-zbornak): `abi.decode()` with the individual args
        // will cause a stack overflow. But we can prefix the call data with an
        // offset to transform it into the encoding for the equivalent single struct arg.
        // Decoding a single struct consumes far less stack space.
        TransformERC20Args memory args;
        {
            bytes memory encodedStructArgs = new bytes(state.mtx.callData.length - 4 + 32);
            // Copy the args data from the original, after the new struct offset prefix.
            bytes memory fromCallData = state.mtx.callData;
            assert(fromCallData.length >= 4);
            uint256 fromMem;
            uint256 toMem;
            assembly {
                // Prefix the original calldata with a struct offset,
                // which is just one word over.
                mstore(add(encodedStructArgs, 32), 32)
                // Copy everything after the selector.
                fromMem := add(fromCallData, 36)
                // Start copying after the struct offset.
                toMem := add(encodedStructArgs, 64)
            }
            LibBytesV06.memCopy(toMem, fromMem, fromCallData.length - 4);
            // Decode call args for `ITransformERC20.transformERC20()` as a struct.
            args = abi.decode(encodedStructArgs, (TransformERC20Args));
        }
        // Call `ITransformERC20._transformERC20()` (internal variant).
        return _callSelf(
            state.hash,
            abi.encodeWithSelector(
                ITransformERC20._transformERC20.selector,
                keccak256(state.mtx.callData),
                state.mtx.signer, // taker is mtx signer
                args.inputToken,
                args.outputToken,
                args.inputTokenAmount,
                args.minOutputTokenAmount,
                args.transformations
            ),
            state.mtx.value
        );
    }

    /// @dev Make an arbitrary internal, meta-transaction call.
    ///      Warning: Do not let unadulerated `callData` into this function.
    function _callSelf(bytes32 hash, bytes memory callData, uint256 value)
        private
        returns (bytes memory returnData)
    {
        bool success;
        (success, returnData) = address(this).call{value: value}(callData);
        if (!success) {
            LibMetaTransactionsRichErrors.MetaTransactionCallFailedError(
                hash,
                callData,
                returnData
            ).rrevert();
        }
    }
}