// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract PatchedBridge {
    using ECDSA for bytes32;
    address public owner;

    constructor(address _owner) {
        owner = _owner;
    }

    function hashMessage(address user, uint256 amount) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(user, amount));
    }

    // Patched: uses Ethereum signed message prefix before recover
    function withdraw(uint256 amount, bytes memory signature) public {
        bytes32 message = hashMessage(msg.sender, amount).toEthSignedMessageHash();
        address signer = message.recover(signature); // recovers signer for prefixed digest
        require(signer == owner, "unauthorized");
        payable(msg.sender).transfer(amount);
    }

    receive() external payable {}
}
