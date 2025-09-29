// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract VulnerableBridge {
    using ECDSA for bytes32;
    address public owner;

    constructor(address _owner) {
        owner = _owner;
    }

    function hashMessage(address user, uint256 amount) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(user, amount));
    }

    // Vulnerable: recovers signer from RAW hash (no Ethereum prefix)
    function withdraw(uint256 amount, bytes memory signature) public {
        bytes32 message = hashMessage(msg.sender, amount);
        address signer = message.recover(signature); // ecrecover(rawHash, sig)
        require(signer == owner, "unauthorized");
        payable(msg.sender).transfer(amount);
    }

    receive() external payable {}
}
