// SPDX-License-Identifier: None

// credit to @dmfxyz:
// https://github.com/dmfxyz/murky/blob/main/differential_testing/test/utils/Strings2.sol

pragma solidity 0.8.13;

library ByteStrings {

    /**
    * @notice Slices the `data` argument from its `offset` index (inclusive) returning a bytes
    *         array of length abs(`length`). If `length` is negative then the slice is copied
    *         backwards.
    *
    * @dev It can return 'inverted slices' where `length` < 0 in order to better
    *      accomodate switching between big and little endianness in incompatible systems.
    *
    * @param data The data to be sliced, in bytes.
    *
    * @param offset The start index of the slice (inclusive).
    *
    * @param length The length of the slice.
    *
    * @return A new 'bytes' variable containing the slice.
    */
    function _slice(
        bytes memory data,
        uint256 offset,
        int256 length
    ) internal pure returns (bytes memory) {
        uint256 dataLength = data.length;
        uint256 lengthAbsolute = length > 0 ? uint256(length) : uint256(-length);

        if (length > 0) {
            if (offset + lengthAbsolute > dataLength) {
                revert();
            }

            bytes memory dataSlice = new bytes(lengthAbsolute);

            for (uint256 i = 0; i < lengthAbsolute; ++i) {
                dataSlice[i] = data[offset + i];
            }

            return dataSlice;
        } else {
            if (offset + 1 < lengthAbsolute) {
                revert();
            }

            bytes memory dataSlice = new bytes(lengthAbsolute);

            for (uint256 i = 0; i < lengthAbsolute; ++i) {
                dataSlice[i] = data[offset - i];
            }

            return dataSlice;
        }
    }

    ///@dev converts bytes array to its ASCII hex string representation
    /// TODO: Definitely more efficient way to do this by processing multiple (16?) bytes at once
    /// but really a helper function for the tests, efficiency not key.
    function toHexString(bytes memory input) public pure returns (string memory) {
        require(input.length < type(uint256).max / 2 - 1);
        bytes16 symbols = "0123456789abcdef";
        bytes memory hex_buffer = new bytes(2 * input.length + 2);
        hex_buffer[0] = "0";
        hex_buffer[1] = "x";

        uint pos = 2;
        uint256 length = input.length;
        for (uint i = 0; i < length; ++i) {
            uint _byte = uint8(input[i]);
            hex_buffer[pos++] = symbols[_byte >> 4];
            hex_buffer[pos++] = symbols[_byte & 0xf];
        }
        return string(hex_buffer);
    }
}