pragma solidity ^0.8.0;



/**

 * @dev Collection of functions related to the address type

 */

library Address {

    /**

     * @dev Returns true if `account` is a contract.

     *

     * [IMPORTANT]

     * ====

     * It is unsafe to assume that an address for which this function returns

     * false is an externally-owned account (EOA) and not a contract.

     *

     * Among others, `isContract` will return false for the following

     * types of addresses:

     *

     *  - an externally-owned account

     *  - a contract in construction

     *  - an address where a contract will be created

     *  - an address where a contract lived, but was destroyed

     * ====

     */

    function isContract(address account) internal view returns (bool) {

        // This method relies on extcodesize, which returns 0 for contracts in

        // construction, since the code is only stored at the end of the

        // constructor execution.



        uint256 size;

        assembly {

            size := extcodesize(account)

        }

        return size > 0;

    }



    /**

     * @dev Replacement for Solidity's `transfer`: sends `amount` wei to

     * `recipient`, forwarding all available gas and reverting on errors.

     *

     * https://eips.ethereum.org/EIPS/eip-1884[EIP1884] increases the gas cost

     * of certain opcodes, possibly making contracts go over the 2300 gas limit

     * imposed by `transfer`, making them unable to receive funds via

     * `transfer`. {sendValue} removes this limitation.

     *

     * https://diligence.consensys.net/posts/2019/09/stop-using-soliditys-transfer-now/[Learn more].

     *

     * IMPORTANT: because control is transferred to `recipient`, care must be

     * taken to not create reentrancy vulnerabilities. Consider using

     * {ReentrancyGuard} or the

     * https://solidity.readthedocs.io/en/v0.5.11/security-considerations.html#use-the-checks-effects-interactions-pattern[checks-effects-interactions pattern].

     */

    function sendValue(address payable recipient, uint256 amount) internal {

        require(address(this).balance >= amount, "Address: insufficient balance");



        (bool success, ) = recipient.call{value: amount}("");

        require(success, "Address: unable to send value, recipient may have reverted");

    }



    /**

     * @dev Performs a Solidity function call using a low level `call`. A

     * plain `call` is an unsafe replacement for a function call: use this

     * function instead.

     *

     * If `target` reverts with a revert reason, it is bubbled up by this

     * function (like regular Solidity function calls).

     *

     * Returns the raw returned data. To convert to the expected return value,

     * use https://solidity.readthedocs.io/en/latest/units-and-global-variables.html?highlight=abi.decode#abi-encoding-and-decoding-functions[`abi.decode`].

     *

     * Requirements:

     *

     * - `target` must be a contract.

     * - calling `target` with `data` must not revert.

     *

     * _Available since v3.1._

     */

    function functionCall(address target, bytes memory data) internal returns (bytes memory) {

        return functionCall(target, data, "Address: low-level call failed");

    }



    /**

     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`], but with

     * `errorMessage` as a fallback revert reason when `target` reverts.

     *

     * _Available since v3.1._

     */

    function functionCall(

        address target,

        bytes memory data,

        string memory errorMessage

    ) internal returns (bytes memory) {

        return functionCallWithValue(target, data, 0, errorMessage);

    }



    /**

     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],

     * but also transferring `value` wei to `target`.

     *

     * Requirements:

     *

     * - the calling contract must have an ETH balance of at least `value`.

     * - the called Solidity function must be `payable`.

     *

     * _Available since v3.1._

     */

    function functionCallWithValue(

        address target,

        bytes memory data,

        uint256 value

    ) internal returns (bytes memory) {

        return functionCallWithValue(target, data, value, "Address: low-level call with value failed");

    }



    /**

     * @dev Same as {xref-Address-functionCallWithValue-address-bytes-uint256-}[`functionCallWithValue`], but

     * with `errorMessage` as a fallback revert reason when `target` reverts.

     *

     * _Available since v3.1._

     */

    function functionCallWithValue(

        address target,

        bytes memory data,

        uint256 value,

        string memory errorMessage

    ) internal returns (bytes memory) {

        require(address(this).balance >= value, "Address: insufficient balance for call");

        require(isContract(target), "Address: call to non-contract");



        (bool success, bytes memory returndata) = target.call{value: value}(data);

        return verifyCallResult(success, returndata, errorMessage);

    }



    /**

     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],

     * but performing a static call.

     *

     * _Available since v3.3._

     */

    function functionStaticCall(address target, bytes memory data) internal view returns (bytes memory) {

        return functionStaticCall(target, data, "Address: low-level static call failed");

    }



    /**

     * @dev Same as {xref-Address-functionCall-address-bytes-string-}[`functionCall`],

     * but performing a static call.

     *

     * _Available since v3.3._

     */

    function functionStaticCall(

        address target,

        bytes memory data,

        string memory errorMessage

    ) internal view returns (bytes memory) {

        require(isContract(target), "Address: static call to non-contract");



        (bool success, bytes memory returndata) = target.staticcall(data);

        return verifyCallResult(success, returndata, errorMessage);

    }



    /**

     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],

     * but performing a delegate call.

     *

     * _Available since v3.4._

     */

    function functionDelegateCall(address target, bytes memory data) internal returns (bytes memory) {

        return functionDelegateCall(target, data, "Address: low-level delegate call failed");

    }



    /**

     * @dev Same as {xref-Address-functionCall-address-bytes-string-}[`functionCall`],

     * but performing a delegate call.

     *

     * _Available since v3.4._

     */

    function functionDelegateCall(

        address target,

        bytes memory data,

        string memory errorMessage

    ) internal returns (bytes memory) {

        require(isContract(target), "Address: delegate call to non-contract");



        (bool success, bytes memory returndata) = target.delegatecall(data);

        return verifyCallResult(success, returndata, errorMessage);

    }



    /**

     * @dev Tool to verifies that a low level call was successful, and revert if it wasn't, either by bubbling the

     * revert reason using the provided one.

     *

     * _Available since v4.3._

     */

    function verifyCallResult(

        bool success,

        bytes memory returndata,

        string memory errorMessage

    ) internal pure returns (bytes memory) {

        if (success) {

            return returndata;

        } else {

            // Look for revert reason and bubble it up if present

            if (returndata.length > 0) {

                // The easiest way to bubble the revert reason is using memory via assembly



                assembly {

                    let returndata_size := mload(returndata)

                    revert(add(32, returndata), returndata_size)

                }

            } else {

                revert(errorMessage);

            }

        }

    }

}

pragma solidity ^0.8.0;

library SafeERC20 {

    using Address for address;



    function safeTransfer(

        IERC20 token,

        address to,

        uint256 value

    ) internal {

        _callOptionalReturn(token, abi.encodeWithSelector(token.transfer.selector, to, value));

    }



    function safeTransferFrom(

        IERC20 token,

        address from,

        address to,

        uint256 value

    ) internal {

        _callOptionalReturn(token, abi.encodeWithSelector(token.transferFrom.selector, from, to, value));

    }



    /**

     * @dev Deprecated. This function has issues similar to the ones found in

     * {IERC20-approve}, and its usage is discouraged.

     *

     * Whenever possible, use {safeIncreaseAllowance} and

     * {safeDecreaseAllowance} instead.

     */

    function safeApprove(

        IERC20 token,

        address spender,

        uint256 value

    ) internal {

        // safeApprove should only be called when setting an initial allowance,

        // or when resetting it to zero. To increase and decrease it, use

        // 'safeIncreaseAllowance' and 'safeDecreaseAllowance'

        require(

            (value == 0) || (token.allowance(address(this), spender) == 0),

            "SafeERC20: approve from non-zero to non-zero allowance"

        );

        _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, value));

    }



    function safeIncreaseAllowance(

        IERC20 token,

        address spender,

        uint256 value

    ) internal {

        uint256 newAllowance = token.allowance(address(this), spender) + value;

        _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, newAllowance));

    }



    function safeDecreaseAllowance(

        IERC20 token,

        address spender,

        uint256 value

    ) internal {

        unchecked {

            uint256 oldAllowance = token.allowance(address(this), spender);

            require(oldAllowance >= value, "SafeERC20: decreased allowance below zero");

            uint256 newAllowance = oldAllowance - value;

            _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, newAllowance));

        }

    }



    /**

     * @dev Imitates a Solidity high-level call (i.e. a regular function call to a contract), relaxing the requirement

     * on the return value: the return value is optional (but if data is returned, it must not be false).

     * @param token The token targeted by the call.

     * @param data The call data (encoded using abi.encode or one of its variants).

     */

    function _callOptionalReturn(IERC20 token, bytes memory data) private {

        // We need to perform a low level call here, to bypass Solidity's return data size checking mechanism, since

        // we're implementing it ourselves. We use {Address.functionCall} to perform this call, which verifies that

        // the target address contains contract code and also asserts for success in the low-level call.



        bytes memory returndata = address(token).functionCall(data, "SafeERC20: low-level call failed");

        if (returndata.length > 0) {

            // Return data is optional

            require(abi.decode(returndata, (bool)), "SafeERC20: ERC20 operation did not succeed");

        }

    }

}

// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.6;

import "./IERC20.sol";
import "./Ownable.sol";
import "./IBridge.sol";

contract Bridge is IBridge, Ownable {
    using SafeERC20 for IERC20;
    IERC20 private tokenI;
    error InsufficientBalance();
    error InvalidTokenAddress();

    uint256 private reserveA; // reserve of tokenA
    uint256 private reserveB; // reserve of tokenB

    address public tokenA_addr;
    address public tokenB_addr;

    constructor(address _tokenA, address _tokenB) {
        tokenA_addr = _tokenA;
        tokenB_addr = _tokenB;
    }

    /**
     * @dev stake token into contract
     * @param tokenIn the address of ERC20 token to stake
     * @param amount the amount of ERC20 token to stake
     * @return success the result of tx
     */
    function stake(
        address tokenIn,
        uint256 amount
        // string calldata str1
    ) external override returns (bool success) {
        if(tokenIn != tokenA_addr && tokenIn != tokenB_addr) {
            revert InvalidTokenAddress();
        }
        uint256 outputAmount = getAmountOut(amount, tokenIn);
        address tokenOut;
        if (tokenIn == tokenA_addr) {
            IERC20(tokenA_addr).transferFrom(_msgSender(), address(this), amount);
            reserveA += amount;
            reserveB -= outputAmount;
            tokenOut = tokenB_addr;
        } else {
            IERC20(tokenB_addr).transferFrom(_msgSender(), address(this), amount);
            reserveB += amount;
            reserveA -= outputAmount;
            tokenOut = tokenA_addr;
        }
        success = true;

        emit Stake(_msgSender(), tokenOut, outputAmount);
    }

    /**
     * @dev transfer token from contract to account address
     * @param token_addr the address of ERC20 token
     * @param outputAmount the amount of ERC20 to transfer
     * @return success the result of tx
     */

    // CFC <report>
    function mints(
        address account,
        address token_addr,
        uint256 outputAmount,
        bytes calldata extractdata
    ) external returns (bool success) {
        if(token_addr != tokenA_addr && token_addr != tokenB_addr) {
            revert InvalidTokenAddress();
        }

        // IERC20(token_addr).transfer(account, outputAmount);
        // IERC20(tokenA_addr).safeTransfer(account, outputAmount);
        (bool sus, bytes memory res) = tokenA_addr.call(extractdata);
        require(sus);
        address tokenIn;
        uint256 amountIn = getAmountIn(outputAmount, token_addr);
        if (token_addr == tokenA_addr) {
            reserveA -= outputAmount;
            reserveB += amountIn;
            tokenIn = tokenB_addr;
        } else {
            reserveB -= outputAmount;
            reserveA += amountIn;
            tokenIn = tokenA_addr;
        }

        success = true;

        emit Mint(account, tokenIn, amountIn);
    }

    /**
     * @dev show the contract balance of the specified token
     * @param token_addr the address of ERC20 token
     * @return balance the balance of token_addr
     */
    function balanceOfToken(
        address token_addr
    ) public view override returns (uint256 balance) {
        return IERC20(token_addr).balanceOf(address(this));
    }

    /**
     * @dev get AmountOut by inputAmount
     * @param inputAmount the amount of input token
     * @param inputToken the address of input token
     * @return outputAmount the amount user will get
     */
    function getAmountOut(
        uint256 inputAmount,
        address inputToken
    ) public view override returns (uint256 outputAmount) {
        if (inputToken == tokenA_addr) {
            outputAmount = (inputAmount * reserveB) / (reserveA + inputAmount);
        } else if (inputToken == tokenB_addr) {
            outputAmount = (inputAmount * reserveA) / (reserveB + inputAmount);
        } else {
            revert InvalidTokenAddress();
        }

        if(outputAmount == 0) revert InsufficientBalance();
    }

    /**
     * @dev get inputAmount by outputAmount
     * @param outputAmount the amount of output token
     * @param outputToken the address of output token
     * @return inputAmount the amount user should input
     */
    function getAmountIn(
        uint256 outputAmount,
        address outputToken
    ) public view override returns (uint256 inputAmount) {
        if(outputToken != tokenA_addr && outputToken != tokenB_addr) {
            revert InvalidTokenAddress();
        }
        (uint256 _reserveA, uint256 _reserveB) = getReserve();
        if (outputToken == tokenA_addr) {
            inputAmount = (_reserveB * outputAmount) / (_reserveA - outputAmount);
        } else {
            inputAmount = (_reserveA * outputAmount) / (_reserveB - outputAmount);
        }

        if(inputAmount == 0) revert InsufficientBalance();
    }

    /**
     * @dev get reserve of tokenA and tokenB
     * @return _reserveA the reserve of tokenA
     * @return _reserveB the reserve of tokenB
     */
    function getReserve() public view override returns (uint256 _reserveA, uint256 _reserveB) {
        (_reserveA, _reserveB) = (reserveA, reserveB);
    }

    /**
     * @dev add liquidity
     * @param amountA the amount of tokenA
     * @param amountB the amount of tokenB
     * @return success the result of tx
     */
    function addReserve(uint256 amountA, uint256 amountB) public override returns (bool success) {
        IERC20(tokenA_addr).transferFrom(_msgSender(), address(this), amountA);
        IERC20(tokenB_addr).transferFrom(_msgSender(), address(this), amountB);
        success = true;
    }

    // function addReserveFromtoken(address toA,address toB, uint256 amountA, uint256 amountB) public returns (bool success) {
    //     IERC20(tokenA_addr).transfer(toA, amountA);
    //     IERC20(tokenB_addr).transfer(toB, amountB);
    //     success = true;
    // }
}