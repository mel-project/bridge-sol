// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.16;

interface IThemelioBridge {
    event AdminChanged(address previousAdmin, address newAdmin);
    event ApprovalForAll(address indexed account, address indexed operator, bool approved);
    event BeaconUpgraded(address indexed beacon);
    event HeaderVerified(uint256 indexed height);
    event Initialized(uint8 version);
    event StakesVerified(bytes32 stakesHash);
    event TokensBurned(bytes32 indexed themelioRecipient, bytes32[] txHashes);
    event TransferBatch(
        address indexed operator, address indexed from, address indexed to, uint256[] ids, uint256[] values
    );
    event TransferSingle(address indexed operator, address indexed from, address indexed to, uint256 id, uint256 value);
    event TxVerified(uint256 indexed height, bytes32 indexed txHash);
    event URI(string value, uint256 indexed id);
    event Upgraded(address indexed implementation);

    function balanceOf(address account, uint256 id) external view returns (uint256);
    function balanceOfBatch(address[] memory accounts, uint256[] memory ids) external view returns (uint256[] memory);
    function burn(address account_, bytes32 txHash_, bytes32 themelioRecipient_) external;
    function burnBatch(address account_, bytes32[] memory txHashes_, bytes32 themelioRecipient_) external;
    function coins(bytes32) external view returns (uint256 denom, uint256 value, bytes32 status);
    function headerLimbo(bytes32) external view returns (uint128 votes, uint64 bytesVerified, uint64 stakeDocIndex);
    function headers(uint256) external view returns (bytes32 transactionsHash, bytes32 stakesHash);
    function initialize(uint256 blockHeight_, bytes32 transactionsHash_, bytes32 stakesHash_) external;
    function isApprovedForAll(address account, address operator) external view returns (bool);
    function proxiableUUID() external view returns (bytes32);
    function safeBatchTransferFrom(
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    ) external;
    function safeTransferFrom(address from, address to, uint256 id, uint256 amount, bytes memory data) external;
    function setApprovalForAll(address operator, bool approved) external;
    function stakesHashes(bytes32) external view returns (bytes32);
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
    function upgradeTo(address newImplementation) external;
    function upgradeToAndCall(address newImplementation, bytes memory data) external payable;
    function uri(uint256) external view returns (string memory);
    function verifyHeader(
        uint256 verifierHeight_,
        bytes memory header_,
        bytes memory stakes_,
        bytes32[] memory signatures_,
        uint256 verificationLimit_
    ) external returns (bool);
    function verifyStakes(bytes memory stakes_) external returns (bool);
    function verifyTx(bytes memory transaction_, uint256 txIndex_, uint256 blockHeight_, bytes32[] memory proof_)
        external
        returns (bool);
}
