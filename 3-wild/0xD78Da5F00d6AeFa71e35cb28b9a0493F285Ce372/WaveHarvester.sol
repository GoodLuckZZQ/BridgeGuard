pragma solidity >=0.8.0 <0.9.0;
//SPDX-License-Identifier: MIT
// Forked from the harvest.art contract
// Upgraded to include more convenience mechanisms and gas efficiency for bulk harvesting single contracts

// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣴⣶⠾⠿⠿⠯⣷⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣼⣾⠛⠁⠀⠀⠀⠀⠀⠀⠈⢻⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠿⠁⠀⠀⠀⢀⣤⣾⣟⣛⣛⣶⣬⣿⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⠟⠃⠀⠀⠀⠀⠀⣾⣿⠟⠉⠉⠉⠉⠛⠿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⡟⠋⠀⠀⠀⠀⠀⠀⠀⣿⡏⣤⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⣠⡿⠛⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⣷⡍⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣤⣤⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⣠⣼⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠷⣤⣤⣠⣤⣤⡤⡶⣶⢿⠟⠹⠿⠄⣿⣿⠏⠀⣀⣤⡦⠀⠀⠀⠀⣀⡄
// ⢀⣄⣠⣶⣿⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠓⠚⠋⠉⠀⠀⠀⠀⠀⠀⠈⠛⡛⡻⠿⠿⠙⠓⢒⣺⡿⠋⠁
// ⠉⠉⠉⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠁⠀

import "./Ownable.sol";
import "./Pausable.sol";
import "./ReentrancyGuard.sol";
import "./IERC20.sol";

interface ERCBase {
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
    function isApprovedForAll(address account, address operator) external view returns (bool);
}

interface ERC721Partial is ERCBase {
    function transferFrom(address from, address to, uint256 tokenId) external;
}

interface ERC1155Partial is ERCBase {
    function safeTransferFrom(address from, address to, uint256 id, uint256 amount, bytes calldata) external;
}

contract WaveHarvester is ReentrancyGuard, Pausable, Ownable {

    bytes4 _ERC721 = 0x80ac58cd;
    bytes4 _ERC1155 = 0xd9b67a26;

    address public lake = address(0);
    uint256 public defaultPrice = 1 gwei;
    uint256 public maxTokensPerTx = 100;

    mapping (address => uint256) private _contractPrices;

    function setlake(address _lake) onlyOwner public {
        lake = _lake;
    }

    function setDefaultPrice(uint256 _defaultPrice) onlyOwner public {
        defaultPrice = _defaultPrice;
    }

    function setMaxTokensPerTx(uint256 _maxTokensPerTx) onlyOwner public {
        maxTokensPerTx = _maxTokensPerTx;
    }

    function setPriceByContract(address contractAddress, uint256 price) onlyOwner public {
        _contractPrices[contractAddress] = price;
    }

    function pause() onlyOwner public {
        _pause();
    }

    function unpause() onlyOwner public {
        _unpause();
    }

    function _getPrice(address contractAddress) internal view returns (uint256) {
        if (_contractPrices[contractAddress] > 0)
            return _contractPrices[contractAddress];
        else
            return defaultPrice;
    }

    function batchTransfer721(address tokenContractToHarvest, uint256[] calldata tokenIds) external whenNotPaused {
        require(lake != address(0), "lake cannot be the 0x0 address");

        ERCBase tokenContract = ERCBase(tokenContractToHarvest);
        require(tokenContract.supportsInterface(_ERC721), "must support 721");
        uint256 tokenPrice = _getPrice(tokenContractToHarvest);
        uint256 totalTokens = 0;
        uint256 totalPrice = 0;

        require(tokenIds.length > 0, ">0 IDs");
        require(tokenContract.isApprovedForAll(msg.sender, address(this)), "Token not yet approved for all transfers");


        for (uint256 i = 0; i < tokenIds.length; i++) {
            totalTokens += 1;
            totalPrice += tokenPrice;

            require(totalTokens < maxTokensPerTx, "Maximum token count reached.");
            require(address(this).balance > totalPrice, "Not enough ether in contract.");

            ERC721Partial(tokenContractToHarvest).transferFrom(msg.sender, lake, tokenIds[i]);
        }

        (bool sent, ) = payable(msg.sender).call{ value: totalPrice }("");
        require(sent, "Failed to send ether.");
    }

    function batchTransfer1155(address tokenContractToHarvest, uint256[] calldata tokenIds, uint256[] calldata counts) external whenNotPaused {
        require(lake != address(0), "lake cannot be the 0x0 address");

        ERCBase tokenContract = ERCBase(tokenContractToHarvest);
        require(tokenContract.supportsInterface(_ERC1155), "must support 1155");

        uint256 tokenPrice = _getPrice(tokenContractToHarvest);
        uint256 totalTokens = 0;
        uint256 totalPrice = 0;
        require(tokenIds.length > 0 && (tokenIds.length == counts.length), "All params must have equal length");
        require(tokenContract.isApprovedForAll(msg.sender, address(this)), "Token not yet approved for all transfers");


        for (uint256 i = 0; i < tokenIds.length; i++) {
            require(counts[i] > 0, "Token count must be greater than zero.");

            totalTokens += counts[i];
            totalPrice += tokenPrice * counts[i];


            require(totalTokens < maxTokensPerTx, "Maximum token count reached.");
            require(address(this).balance > totalPrice, "Not enough ether in contract.");

            ERC1155Partial(tokenContractToHarvest).safeTransferFrom(msg.sender, lake, tokenIds[i], counts[i], "");    
        }

        (bool sent, ) = payable(msg.sender).call{ value: totalPrice }("");
        require(sent, "Failed to send ether.");
    }

    function batchTransfer(address[] calldata tokenContracts, uint256[] calldata tokenIds, uint256[] calldata counts) external whenNotPaused {
        require(lake != address(0), "lake cannot be the 0x0 address");
        require(tokenContracts.length > 0, "Must have 1 or more token contracts");
        require(tokenContracts.length == tokenIds.length && tokenIds.length == counts.length, "All params must have equal length");

        ERCBase tokenContract;
        uint256 totalTokens = 0;
        uint256 totalPrice = 0;

        for (uint256 i = 0; i < tokenContracts.length; i++) {
            require(counts[i] > 0, "Token count must be greater than zero.");

            tokenContract = ERCBase(tokenContracts[i]);

            if (tokenContract.supportsInterface(_ERC721)) {
                totalTokens += 1;
                totalPrice += _getPrice(tokenContracts[i]);
            }
            else if (tokenContract.supportsInterface(_ERC1155)) {
                totalTokens += counts[i];
                totalPrice += _getPrice(tokenContracts[i]) * counts[i];
            }
            else {
                continue;
            }

            require(totalTokens < maxTokensPerTx, "Maximum token count reached.");
            require(address(this).balance > totalPrice, "Not enough ether in contract.");
            require(tokenContract.isApprovedForAll(msg.sender, address(this)), "Token not yet approved for all transfers");

            if (tokenContract.supportsInterface(_ERC721)) {
                ERC721Partial(tokenContracts[i]).transferFrom(msg.sender, lake, tokenIds[i]);
            }
            else {
                ERC1155Partial(tokenContracts[i]).safeTransferFrom(msg.sender, lake, tokenIds[i], counts[i], "");
            }
        }

        (bool sent, ) = payable(msg.sender).call{ value: totalPrice }("");
        require(sent, "Failed to send ether.");
    }

    receive () external payable { }

    function recoverERC20ToLake(address tokenAddress, uint256 tokenAmount) public virtual onlyOwner {
        require(lake != address(0), "lake cannot be the 0x0 address");
        IERC20(tokenAddress).transfer(lake, tokenAmount);
    }

    function recoverERC721ToLake(address tokenAddress, uint256 tokenId) public virtual onlyOwner {
        require(lake != address(0), "lake cannot be the 0x0 address");
        ERC721Partial(tokenAddress).transferFrom(address(this), lake, tokenId);
    }

    function recoverERC1155ToLake(address tokenAddress, uint256 tokenId, uint256 count) public virtual onlyOwner {
        require(lake != address(0), "lake cannot be the 0x0 address");
        ERC1155Partial(tokenAddress).safeTransferFrom(address(this), lake, tokenId, count, "");
    }

    function withdrawBalance() external onlyOwner {
        payable(msg.sender).transfer(address(this).balance);
    }
}