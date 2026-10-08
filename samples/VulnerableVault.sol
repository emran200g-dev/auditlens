// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

contract VulnerableVault {
    address public owner;
    mapping(address => uint256) public balances;
    bool public paused;

    constructor() { owner = msg.sender; }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // Sends ETH before zeroing the balance
    function withdraw() external {
        uint256 amt = balances[msg.sender];
        (bool ok,) = msg.sender.call{value: amt}("");
        require(ok);
        balances[msg.sender] = 0;
    }

    function setOwner(address n) external {
        owner = n;
    }

    function emergencyDrain(address payable to) external {
        require(tx.origin == owner, "not owner");
        to.send(address(this).balance);
    }

    function mint(address to, uint256 a) external onlyOwner {
        balances[to] += a;
    }

    function pause() external onlyOwner { paused = true; }

    function lottery() external payable {
        if (uint256(keccak256(abi.encode(block.timestamp))) % 2 == 0) {
            balances[msg.sender] += msg.value * 2;
        }
    }

    modifier onlyOwner() { require(msg.sender == owner); _; }
}
