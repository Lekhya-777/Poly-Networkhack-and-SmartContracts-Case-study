// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * SecureManager implements access controls to prevent arbitrary external calls.
 * It maintains whitelists of allowed target addresses and function selectors,
 * ensuring only authorized calls can be executed through the manager.
 */
contract SecureManager {
    address public admin;
    mapping(address => bool) public allowedTargets;
    mapping(bytes4 => bool) public allowedSelectors;
    
    event TargetAllowed(address target, bool allowed);
    event SelectorAllowed(bytes4 selector, bool allowed);
    
    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }
    
    constructor() {
        admin = msg.sender;
    }
    
    function setAllowedTarget(address target, bool allowed) external onlyAdmin {
        allowedTargets[target] = allowed;
        emit TargetAllowed(target, allowed);
    }
    
    function setAllowedSelector(bytes4 selector, bool allowed) external onlyAdmin {
        allowedSelectors[selector] = allowed;
        emit SelectorAllowed(selector, allowed);
    }
    
    /**
     * Executes external calls only if both target address and function selector are allowed.
     * This prevents arbitrary calls while still allowing controlled interactions.
     */
    function exec(address to, bytes calldata data) external returns (bytes memory) {
        require(allowedTargets[to], "Target not allowed");
        
        bytes4 selector = bytes4(data);
        require(allowedSelectors[selector], "Selector not allowed");
        
        (bool ok, bytes memory res) = to.call(data);
        require(ok, "Call failed");
        return res;
    }
}
