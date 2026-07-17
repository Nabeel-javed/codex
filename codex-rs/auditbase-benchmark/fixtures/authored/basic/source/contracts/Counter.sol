// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

contract Counter {
    uint256 public value;

    function increment() external {
        value += 1;
    }
}
