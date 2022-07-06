// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.13;

interface IThemelioBridge {
    function balanceOf(
        address account,
        uint256 id
    ) external view returns (uint256);

    function balanceOfBatch(
        address[] calldata accounts,
        uint256[] calldata ids
    ) external view returns (uint256[] memory);

    function burn (
        address account_,
        uint256 id_,
        uint256 value_,
        bytes32 themelioRecipient_
    ) external;

    function burnBatch(
        address account_,
        uint256[] calldata ids_,
        uint256[] calldata values_,
        bytes32 themelioRecipient_
    ) external;

    function headerLimbo(bytes32) external view returns (
        uint128 votes,
        uint64 bytesVerified,
        uint64 stakeDocIndex
    );

    function headers(uint256) external view returns (bytes32 transactionsHash, bytes32 stakesHash);

    function initialize(
        uint256 blockHeight_,
        bytes32 transactionsHash_,
        bytes32 stakesHash_
    ) external;

    function isApprovedForAll(address account, address operator) external view returns (bool);

    function owner() external view returns (address);

    function proxiableUUID() external view returns (bytes32);

    function renounceOwnership() external;

    function safeBatchTransferFrom(
        address from,
        address to,
        uint256[] calldata ids,
        uint256[] calldata amounts,
        bytes calldata data
    ) external;

    function safeTransferFrom(
        address from,
        address to,
        uint256 id,
        uint256 amount,
        bytes calldata data
    ) external;

    function setApprovalForAll(address operator, bool approved) external;

    function spends(bytes32) external view returns (bool);

    function supportsInterface(bytes4 interfaceId) external view returns (bool);

    function transferOwnership(address newOwner) external;

    function upgradeTo(address newImplementation) external;

    function upgradeToAndCall(address newImplementation, bytes memory data) external;

    function uri(uint256) external view returns (string memory);

    function verifyHeader(
        uint256 verifierHeight_,
        bytes calldata header_,
        bytes calldata stakes_,
        bytes32[] calldata signatures_,
        bool firstTime_
    ) external returns (bool);

    function verifyStakes(bytes calldata stakes_) external returns (bool);

    function verifyTx(
        bytes calldata transaction_,
        uint256 txIndex_,
        uint256 blockHeight_,
        bytes32[] calldata proof_
    ) external returns (bool);
}