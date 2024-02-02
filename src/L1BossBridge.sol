// __| |_____________________________________________________| |__
// __   _____________________________________________________   __
//   | |                                                     | |
//   | | ____                  ____       _     _            | |
//   | || __ )  ___  ___ ___  | __ ) _ __(_) __| | __ _  ___ | |
//   | ||  _ \ / _ \/ __/ __| |  _ \| '__| |/ _` |/ _` |/ _ \| |
//   | || |_) | (_) \__ \__ \ | |_) | |  | | (_| | (_| |  __/| |
//   | ||____/ \___/|___/___/ |____/|_|  |_|\__,_|\__, |\___|| |
//   | |                                          |___/      | |
// __| |_____________________________________________________| |__
// __   _____________________________________________________   __
//   | |                                                     | |

// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import { IERC20 } from "@openzeppelin/contracts/interfaces/IERC20.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { Pausable } from "@openzeppelin/contracts/utils/Pausable.sol";
import { ReentrancyGuard } from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

import { L1Vault } from "./L1Vault.sol";

contract L1BossBridge is Ownable, Pausable, ReentrancyGuard {
    using SafeERC20 for IERC20;

    //@audit-info should be a constant variable
    uint256 public DEPOSIT_LIMIT = 100_000 ether;

    IERC20 public immutable token; // e one bridge per token
    L1Vault public immutable vault; // e one vault per bridge
    mapping(address account => bool isSigner) public signers; // e signers are users who can send a token from L1 to L2

    error L1BossBridge__DepositLimitReached();
    error L1BossBridge__Unauthorized();
    error L1BossBridge__CallFailed();

    event Deposit(address from, address to, uint256 amount);

    constructor(IERC20 _token) Ownable(msg.sender) {
        token = _token;
        vault = new L1Vault(token);
        // Allows the bridge to move tokens out of the vault to facilitate withdrawals
        vault.approveTo(address(this), type(uint256).max);
    }

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }

    // e The owner can enable or disable addresses as signers
    // q what happens if we disbale an account mid-transaction?
    function setSigner(address account, bool enabled) external onlyOwner {
        signers[account] = enabled;
    }

    /*
     * @notice Locks tokens in the vault and emits a Deposit event
     * the unlock event will trigger the L2 minting process. There are nodes listening
     * for this event and will mint the corresponding tokens on L2. This is a centralized process.
     * 
     * @param from The address of the user who is depositing tokens
     * @param l2Recipient The address of the user who will receive the tokens on L2
     * @param amount The amount of tokens to deposit
     */
    // @audit high - arbitrary 'from' in safeTransferFrom - in this scenario a user is stealing tokens from another user who has approved the bridge
    // e if a user approves the bridge, any other user can steal their funds
    
    // @audit high - users can transfer tokens from the vault to any address - in this scenario as user is stealing tokens from the L2 vault because the L1 vault has approved the bridge to spend tokens
    // e if the vault approved the bridge, can a user steal funds from the vault?

    function depositTokensToL2(address from, address l2Recipient, uint256 amount) external whenNotPaused {
        if (token.balanceOf(address(vault)) + amount > DEPOSIT_LIMIT) { // max vault balance
            revert L1BossBridge__DepositLimitReached();
        }
        token.safeTransferFrom(from, address(vault), amount);

        // Our off-chain service picks up this event and mints the corresponding tokens on L2
        // @audit-info /low this event is emitted after calling safeTransferFrom, should follow CEI and emit before external call
        emit Deposit(from, l2Recipient, amount); // e important event to mint tokens on L2 0
    }

    /*
     * @notice This is the function responsible for withdrawing tokens from L2 to L1.
     * Our L2 will have a similar mechanism for withdrawing tokens from L1 to L2.
     * @notice The signature is required to prevent replay attacks. 
     * 
     * @param to The address of the user who will receive the tokens on L1
     * @param amount The amount of tokens to withdraw
     * @param v The v value of the signature
     * @param r The r value of the signature
     * @param s The s value of the signature
     */

    // e When a signer notices that there were tokens deposited into the L2 vault, they sign a message to withdraw the tokens to L1. \
    // e    This message is represented by 3 components: v, r, and s.
    function withdrawTokensToL1(address to, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        sendToL1(
            v,
            r,
            s,
            abi.encode(
                address(token),
                0, // value
                abi.encodeCall(IERC20.transferFrom, (address(vault), to, amount))
            )
        );
    }

    /*
     * @notice This is the function responsible for withdrawing ETH from L2 to L1.
     *
     * @param v The v value of the signature
     * @param r The r value of the signature
     * @param s The s value of the signature
     * @param message The message/data to be sent to L1 (can be blank)
     */
    function sendToL1(uint8 v, bytes32 r, bytes32 s, bytes memory message) public nonReentrant whenNotPaused {
        address signer = ECDSA.recover(MessageHashUtils.toEthSignedMessageHash(keccak256(message)), v, r, s); // e recover the signer from the signed message

        if (!signers[signer]) {
            revert L1BossBridge__Unauthorized();
        }

        (address target, uint256 value, bytes memory data) = abi.decode(message, (address, uint256, bytes));

        // q slither picked this up as a high, need to check
        // allowing arbitrary calls to be made is dangerous, anyone can approve the bridge to spend tokens from the vault
        // gas bomb: data with a high gas costs can be sent to the bridge, causing a DoS
        (bool success,) = target.call{ value: value }(data);
        if (!success) {
            revert L1BossBridge__CallFailed();
        }
    }
}
