// SPDX-License-Identifier: Apache-2.0.
pragma solidity ^0.6.12;
pragma experimental ABIEncoderV2;

import {Users} from "../src/Users.sol";
import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";

contract UsersTest is Test {

    function test_adminCanGenerateValidSignatures() public {
        // arrange
        Users users = new Users();
        address ethAdd = 0xac3cc5a41D9e8c94Fe64138C1343A07B2fF5ff76;
        // 0x7a88d4e1a357d33d6168058ac6b08fa54c07b72313f78af594d4d44e8268a6c
        uint256 starkKey = 3463995498836494504631329032145085468217956335318243415256427132985150966380;
        bytes memory opSignature = registerAdminAndGetOperatorSignature(users, ethAdd, starkKey);

        // act
        bool result = users.isOperatorSignatureValid(ethAdd, starkKey, opSignature);

        // assert
        require(result, "signature is not valid");
    }

    function test_nonAdminCanNotGenerateValidSignatures() public {
        // arrange
        Users users = new Users();
        uint256 privKey = 77814517325470205911140941194401928579557062014761831930645393041380819009408;
        address nonAdmin = vm.addr(privKey);
        require(!users.isUserAdmin(nonAdmin), "admin is not registered");

        address ethAdd = 0xac3cc5a41D9e8c94Fe64138C1343A07B2fF5ff76;
        // 0x7a88d4e1a357d33d6168058ac6b08fa54c07b72313f78af594d4d44e8268a6c
        uint256 starkKey = 3463995498836494504631329032145085468217956335318243415256427132985150966380;
        bytes memory opSignature = getOperatorSignature(privKey, ethAdd, starkKey);

        // act
        bool result = users.isOperatorSignatureValid(ethAdd, starkKey, opSignature);

        // assert
        require(!result, "signature is valid");
    }

    function test_registeringWithoutOperatorSignatureSetsATimer() public {
        // arrange
        Users users = new Users();
        (address ethAdd, uint256 starkKey, bytes memory regSig) = getAccountA();

        // pre-condition
        require(users.getEthKey(starkKey) == address(0), "user is registered");
        require(users.getRegistrationTimer(starkKey) == 0, "timer is set");

        // act
        users.registerEthAddress(ethAdd, starkKey, regSig);

        // assert
        // user is now registered
        require(users.getEthKey(starkKey) == ethAdd, "user is not registered");

        // timer is set
        require(users.getRegistrationTimer(starkKey) == block.timestamp + 7 days, "timer is not set correctly");
    }

    function test_registeringWithValidOperatorSignatureDoesNotSetATimer() public {
        // arrange
        Users users = new Users();
        (address ethAdd, uint256 starkKey, bytes memory regSig) = getAccountA();
        bytes memory opSignature = registerAdminAndGetOperatorSignature(users, ethAdd, starkKey);

        // pre-condition
        // user is not registered and timer is not set
        require(users.getEthKey(starkKey) == address(0), "user is registered");
        require(users.getRegistrationTimer(starkKey) == 0, "timer is set");

        // act
        users.registerEthAddress(ethAdd, starkKey, regSig, opSignature);

        // assert
        // user is now registered
        require(users.getEthKey(starkKey) == ethAdd, "user is not registered");

        // timer is set
        require(users.getRegistrationTimer(starkKey) == 0, "timer is set when it should not");
    }

    function test_registeringWithoutValidOperatorSignatureCanBeOverridenWithinRegistrationPeriod() public {
        // arrange
        Users users = new Users();
        (address ethAdd, uint256 starkKey, bytes memory regSig) = getAccountA();

        // pre-condition
        // user is not registered and timer is not set
        require(users.getEthKey(starkKey) == address(0), "user is registered");
        require(users.getRegistrationTimer(starkKey) == 0, "timer is set");

        // act
        users.registerEthAddress(ethAdd, starkKey, regSig);

        // assert
        // user is now registered
        require(users.getEthKey(starkKey) == ethAdd, "user is not registered");
        // timer is set
        require(users.getRegistrationTimer(starkKey) == block.timestamp + 7 days, "timer is not set correctly");

        // 2 days later
        uint256 futureTimestamp = block.timestamp + 2 days;
        vm.warp(futureTimestamp);

        // act 2 - allow override because registration is not final yet
        (address ethAdd2, uint256 starkKey2, bytes memory regSig2) = getAccountB();
        require(starkKey == starkKey2, "stark keys are not the same");
        users.registerEthAddress(ethAdd2, starkKey, regSig2);

        // user is now registered towards the new address
        require(users.getEthKey(starkKey) == ethAdd2, "user is not registered correctly");

        // timer is set
        require(users.getRegistrationTimer(starkKey) == futureTimestamp + 7 days, "timer is not set correctly");
    }

    function test_registeringWithoutValidOperatorSignatureCanNotBeOverridenOutsideRegistrationPeriod() public {
        // arrange
        Users users = new Users();
        (address ethAdd, uint256 starkKey, bytes memory regSig) = getAccountA();

        // pre-condition
        // user is not registered and timer is not set
        require(users.getEthKey(starkKey) == address(0), "user is registered");
        require(users.getRegistrationTimer(starkKey) == 0, "timer is set");

        // act
        users.registerEthAddress(ethAdd, starkKey, regSig);

        // assert
        // user is now registered
        require(users.getEthKey(starkKey) == ethAdd, "user is not registered");
        // timer is set
        uint256 expectedTimer = block.timestamp + 7 days;
        require(users.getRegistrationTimer(starkKey) == expectedTimer, "timer is not set correctly");

        // 2 days later
        uint256 futureTimestamp = block.timestamp + 8 days;
        vm.warp(futureTimestamp);

        // override because registration is not final yet
        (address ethAdd2, uint256 starkKey2, bytes memory regSig2) = getAccountB();
        require(starkKey == starkKey2, "stark keys are not the same");

        // assert / act
        vm.expectRevert("SELF_DISPUTE_PERIOD_PASSED");
        users.registerEthAddress(ethAdd2, starkKey, regSig2);
        require(users.getEthKey(starkKey) == ethAdd, "user shouldn't be overriden");
        require(users.getRegistrationTimer(starkKey) == expectedTimer, "timer shouldn't be changed");
    }

    function test_registeringWithValidOperatorSignatureCanNotBeOverriden() public {
        // arrange
        Users users = new Users();
        (address ethAdd, uint256 starkKey, bytes memory regSig) = getAccountA();
        bytes memory opSignature = registerAdminAndGetOperatorSignature(users, ethAdd, starkKey);

        // pre-condition
        // user is not registered and timer is not set
        require(users.getEthKey(starkKey) == address(0), "user is registered");
        require(users.getRegistrationTimer(starkKey) == 0, "timer is set");

        // act
        users.registerEthAddress(ethAdd, starkKey, regSig, opSignature);

        // assert
        // user is now registered
        require(users.getEthKey(starkKey) == ethAdd, "user is not registered");
        // timer is not set because of the operator signature is valid
        require(users.getRegistrationTimer(starkKey) == 0, "timer is not set correctly");

        // 2 days later
        vm.warp(block.timestamp + 2 days);

        (address ethAdd2, uint256 starkKey2, bytes memory regSig2) = getAccountB();
        require(starkKey == starkKey2, "stark keys are not the same");

        // assert / act
        vm.expectRevert("SELF_DISPUTE_PERIOD_PASSED");
        users.registerEthAddress(ethAdd2, starkKey, regSig2);

        // user is wasn't overriden
        require(users.getEthKey(starkKey) == ethAdd, "user shouldn't be overriden");
        // timer is not set
        require(users.getRegistrationTimer(starkKey) == 0, "timer shouldn't be changed");
    }

    function test_registeringWithValidOperatorSignatureCanOverrideOneThatWasNot() public {
        // arrange
        Users users = new Users();
        (address ethAdd, uint256 starkKey, bytes memory regSig) = getAccountA();

        // pre-condition
        require(users.getEthKey(starkKey) == address(0), "user is registered");
        require(users.getRegistrationTimer(starkKey) == 0, "timer is set");

        // act-1
        users.registerEthAddress(ethAdd, starkKey, regSig);

        // assert
        // user is now registered
        require(users.getEthKey(starkKey) == ethAdd, "user is not registered");
        // timer is not set because of the operator signature is valid
        require(users.getRegistrationTimer(starkKey) == block.timestamp + 7 days, "timer is not set correctly");

        // 2 days later
        vm.warp(block.timestamp + 2 days);

        // act-2
        (address ethAdd2, uint256 starkKey2, bytes memory regSig2) = getAccountB();
        require(starkKey == starkKey2, "stark keys are not the same");

        // preparing admin signature
        bytes memory opSignature = registerAdminAndGetOperatorSignature(users, ethAdd2, starkKey);
        // override because registration is not final yet
        users.registerEthAddress(ethAdd2, starkKey, regSig2, opSignature);

        // user is now registered towards the new address
        require(users.getEthKey(starkKey) == ethAdd2, "user should be overriden");
        // timer is reset to 0 because of the operator signature is valid
        require(users.getRegistrationTimer(starkKey) == 0, "timer shouldn't be changed");
    }

    function registerAdminAndGetOperatorSignature(Users users, address ethAdd, uint256 starkKey) private returns (bytes memory) {
        // preparing admin signature
        uint256 privKey = 77814517325470205911140941194401928579557062014761831930645393041380819009408;
        address admin = vm.addr(privKey);
        users.registerUserAdmin(admin);
        require(users.isUserAdmin(admin), "admin is not registered");

        return getOperatorSignature(privKey, ethAdd, starkKey);
    }

    function getOperatorSignature(uint256 privKey, address ethAdd, uint256 starkKey) public pure returns (bytes memory) {
        bytes32 payload = keccak256(abi.encodePacked("UserRegistration:", ethAdd, starkKey));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privKey, payload);
        bytes memory opSignature = abi.encodePacked(r, s, v);
        return opSignature;
    }

    function getAccountA() public pure returns (address, uint256, bytes memory) {
        address ethAdd = 0xac3cc5a41D9e8c94Fe64138C1343A07B2fF5ff76;
        // 0x7a88d4e1a357d33d6168058ac6b08fa54c07b72313f78af594d4d44e8268a6c
        uint256 starkKey = 3463995498836494504631329032145085468217956335318243415256427132985150966380;
        // arrange
        bytes memory regSig = abi.encodePacked(
            uint256(0x06f56e3e7392318ae672ff7d68d1b6c54a6f402019bd121dee9b8d8aa9658ab5), // r
            uint256(0x06c1b98af915c6c1f88ea15f22f2d4f4a7a20c5416cafca0538bf227469dc14a), // s
            uint256(0x02ec99c3c1d90d78dd77676a2505bbeba3cf9ecd1003d72c14949817d84625a4) // starkY
        );

        return (ethAdd, starkKey, regSig);
    }

    function getAccountB() public pure returns (address, uint256, bytes memory) {
        address ethAdd = 0x0eDFFC4C8C640e4D0eEC98c6eC63323F637dAf84;
        // 0x7a88d4e1a357d33d6168058ac6b08fa54c07b72313f78af594d4d44e8268a6c
        uint256 starkKey = 3463995498836494504631329032145085468217956335318243415256427132985150966380;
        // arrange
        bytes memory regSig = abi.encodePacked(
            uint256(0x04dc9a13ad9097f14984fa2313814eca918549efb529d5ca790346ff58b9d9cd), // r
            uint256(0x044823c56342aa560a94b5d0fc0a1e5d227875039d6693d64f9471486c0017b1), // s
            uint256(0x02ec99c3c1d90d78dd77676a2505bbeba3cf9ecd1003d72c14949817d84625a4) // starkY
        );

        return (ethAdd, starkKey, regSig);
    }
}
