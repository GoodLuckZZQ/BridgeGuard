//SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import "./Initializable.sol";
import "./OwnableUpgradeable.sol";

contract Controllable is OwnableUpgradeable {
	// Errors
	error ControllerOnly();

	address private controller;

	modifier onlyController {
		if(_msgSender() != controller && _msgSender() != owner()) revert ControllerOnly();
		_;
	}

	function __init_controller(address _controller) internal virtual onlyInitializing {
		controller = _controller;
		__Ownable_init(controller);
	}

	function changeController(address _controller) external onlyOwner {
		require(_controller != address(0), "Controller cannot be 0 address");
		controller = _controller;
	}
}
