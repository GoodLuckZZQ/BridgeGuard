// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./MerkleProof.sol";
import "./Ownable.sol";
import "./Strings.sol";
import "./ERC721AQueryable.sol";
import "./ERC721ABurnable.sol";
import "./OperatorFilterer.sol";

contract MoonshinersMoonshine is
    ERC721AQueryable,
    ERC721ABurnable,
    Ownable,
    OperatorFilterer
{
    address constant DEFAULT_SUBSCRIPTION =
        address(0x3cc6CddA760b79bAfa08dF41ECFA224f810dCeB6);

    struct MintState {
        uint256 liveAt;
        uint256 expiresAt;
        bytes32 merkleRoot;
        uint256 maxPerWallet;
        uint256 maxSupply;
        uint256 totalSupply;
        uint256 holderPrice;
        uint256 publicPrice;
        uint256 minted;
    }

    // @notice Base URI for the nft
    string private baseURI =
        "https://bafybeibgmnexgghwlmtidiely44t57gia7otx7a7g3uapfk27jnuuvypsi.ipfs.nftstorage.link/metadata.json";

    // @notice The merkle root
    bytes32 public merkleRoot =
        0x9531c62df016a4878212ad9ec2240fb7494fe8883f766d6a7054f0aab2f18b02;

    // @notice Max mints per wallet (n-1)
    uint256 public maxPerWallet = 201;

    // @dev The total supply of the collection (n-1)
    uint256 public maxSupply = 5001;

    // @dev The holder mint price, ~$1
    uint256 public holderPrice = 0.001 ether;

    // @dev The public mint price, ~$5
    uint256 public publicPrice = 0.004 ether;

    // @dev The withdraw address
    address public treasury =
        payable(0xb5164865b185acbB02710D36F18b6513409B8ef5);

    // @notice Live date 12pm PST
    uint256 public liveAt = 1670529600;

    // @notice Expiration date
    uint256 public expiresAt = 1672430400;

    /// @dev Tracks wallet mint count
    mapping(address => uint256) public addressToMinted;

    modifier whitelisted(bytes32[] calldata _proof) {
        bytes32 leaf = keccak256(abi.encodePacked(_msgSender()));
        require(MerkleProof.verify(_proof, merkleRoot, leaf), "Invalid proof.");
        _;
    }

    modifier isLive() {
        require(
            block.timestamp > liveAt && block.timestamp < expiresAt,
            "Mint is not live."
        );
        _;
    }

    modifier withinMintSupply(uint256 _amount) {
        require(
            addressToMinted[_msgSender()] + _amount < maxPerWallet,
            "Max per wallet reached."
        );
        require(
            totalSupply() + _amount < maxSupply,
            "Cannot mint over max supply."
        );
        _;
    }

    modifier correctPrice(uint256 _amount, uint256 _price) {
        require(msg.value >= _amount * _price, "Not enough funds.");
        _;
    }

    constructor()
        ERC721A("MoonshinersMoonshine", "MNSHNM")
        OperatorFilterer(DEFAULT_SUBSCRIPTION, true)
    {
        _mintERC2309(treasury, 1); // Placeholder mint
    }

    /**
     * @notice Whitelist mint
     * @param _proof The bytes32 array proof to verify the merkle root
     */
    function whitelistMint(uint256 _amount, bytes32[] calldata _proof)
        external
        payable
        isLive
        withinMintSupply(_amount)
        correctPrice(_amount, holderPrice)
        whitelisted(_proof)
    {
        addressToMinted[_msgSender()] += _amount;
        _mint(_msgSender(), _amount);
    }

    /**
     * @notice Mints a new token
     * @param _amount The number of tokens to mint
     */
    function mint(uint256 _amount)
        external
        payable
        isLive
        withinMintSupply(_amount)
        correctPrice(_amount, publicPrice)
    {
        addressToMinted[_msgSender()] += _amount;
        _mint(_msgSender(), _amount);
    }

    /**
     * @dev Returns mint state for a particular address
     * @param _address The address
     */
    function getMintState(address _address)
        external
        view
        returns (MintState memory)
    {
        return
            MintState({
                liveAt: liveAt,
                expiresAt: expiresAt,
                merkleRoot: merkleRoot,
                maxPerWallet: maxPerWallet,
                maxSupply: maxSupply,
                totalSupply: totalSupply(),
                holderPrice: holderPrice,
                publicPrice: publicPrice,
                minted: addressToMinted[_address]
            });
    }

    /**
     * @notice Returns the URI for a given token id
     * @param _tokenId A tokenId
     */
    function tokenURI(uint256 _tokenId)
        public
        view
        override
        returns (string memory)
    {
        if (!_exists(_tokenId)) revert OwnerQueryForNonexistentToken();
        return baseURI; // Single reference metadata
    }

    // @dev Overrides the start token id
    function _startTokenId() internal view virtual override returns (uint256) {
        return 1;
    }

    /**
     * @notice Sets holders price
     * @param _holderPrice price in wei
     */
    function setHolderPrice(uint256 _holderPrice) external onlyOwner {
        holderPrice = _holderPrice;
    }

    /**
     * @notice Sets public price
     * @param _publicPrice price in wei
     */
    function setPublicPrice(uint256 _publicPrice) external onlyOwner {
        publicPrice = _publicPrice;
    }

    /**
     * @notice Sets the merkle root for the mint
     * @param _merkleRoot The merkle root to set
     */
    function setMerkleRoot(bytes32 _merkleRoot) external onlyOwner {
        merkleRoot = _merkleRoot;
    }

    /**
     * @notice Sets the base URI of the NFT
     * @param _newBaseURI A base uri
     */
    function setBaseURI(string calldata _newBaseURI) external onlyOwner {
        baseURI = _newBaseURI;
    }

    /**
     * @notice Sets the max per wallet
     * @param _maxPerWallet The max mint count per address
     */
    function setMaxPerWallet(uint256 _maxPerWallet) external onlyOwner {
        maxPerWallet = _maxPerWallet;
    }

    /**
     * @notice Sets the collection max supply
     * @param _maxSupply The max supply of the collection
     */
    function setMaxSupply(uint256 _maxSupply) external onlyOwner {
        maxSupply = _maxSupply;
    }

    /**
     * @notice Sets timestamps for live and expires timeframe
     * @param _liveAt A unix timestamp for live date
     * @param _expiresAt A unix timestamp for expiration date
     */
    function setMintWindow(uint256 _liveAt, uint256 _expiresAt)
        external
        onlyOwner
    {
        liveAt = _liveAt;
        expiresAt = _expiresAt;
    }

    /**
     * @notice Sets the treasury recipient
     * @param _treasury The treasury address
     */
    function setTreasury(address _treasury) external onlyOwner {
        treasury = payable(_treasury);
    }

    /**
     * @notice Withdraws funds from contract
     */
    function withdraw() external onlyOwner {
        (bool success, ) = treasury.call{value: address(this).balance}("");
        require(success, "Failed to send to treasury.");
    }

    /******************************************************************************************************************
     * Royalty enforcement via registry filterer
     ******************************************************************************************************************/

    function setApprovalForAll(address operator, bool approved)
        public
        override
        onlyAllowedOperatorApproval(operator)
    {
        super.setApprovalForAll(operator, approved);
    }

    function approve(address operator, uint256 tokenId)
        public
        virtual
        override
        onlyAllowedOperatorApproval(operator)
    {
        super.approve(operator, tokenId);
    }

    function transferFrom(
        address from,
        address to,
        uint256 tokenId
    ) public override onlyAllowedOperator(from) {
        super.transferFrom(from, to, tokenId);
    }

    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId
    ) public override onlyAllowedOperator(from) {
        super.safeTransferFrom(from, to, tokenId);
    }

    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId,
        bytes memory data
    ) public override onlyAllowedOperator(from) {
        super.safeTransferFrom(from, to, tokenId, data);
    }
}