# Electroneum PHP Wallet Manager

A wallet manager written in PHP to create and verify Electroneum wallet
addresses and keys.

This allows for a PHP only solution; no need to run the wallet-rpc that
requires a synchronised blockchain.

## Requirements
 - PHP 7.0+ (not tested <7)
 - [GMP PHP library](http://php.net/manual/en/book.gmp.php)

## Install

### Manual Installation

Unpack the code and include the Electroneum WalletManager class:

```php
require_once('lib/WalletManager.php');
```

### Composer Installation

Using composer, you can easily install with:

```
composer require electroneum/wallet-manager-php
```

Alternatively, you can add the following to your `composer.json`:

```
"require": {
    "electroneum/wallet-manager-php": "^0.1.0"
},
"repositories": [
    {
        "type": "vcs",
        "url": "https://github.com/electroneum/wallet-manager-php"
    }
],
```

## Demo

A demonstration can be found in ```example/demo.php```.

## Quick Use

The most common use, to generate a new wallet:

        $walletManager = new Electroneum\Wallet\WalletManager();
        $wallet = $walletManager->wallet_from_seed();

## Getting Started

Create the `WalletManager()` object, optionally passing an ISO 639-1 code
for the required mnemonic language:

    // Default to English
    $walletManager = new Electroneum\Wallet\WalletManager();

    // French
    $walletManager = new Electroneum\Wallet\WalletManager('fr');

Supported languages are currently limited to:

| Code | Language   |
|------|------------|
| de   | German     |
| en   | English    |
| eo   | Esperanto  |
| es   | Spanish    |
| fr   | French     |
| it   | Italian    |
| ja   | Japanese   |
| pt   | Portuguese |
| ru   | Russian    |
| zh   | Chinese    |

### Create a Wallet

This accepts an optioan seed (32 hexadecimal string) and returns an
array of seed, mnemonic words, wallet address and spend/view
public/private keys.

    $wallet = $walletManager->wallet_from_seed($seed = null);

### Create a Wallet from Mnemonic Words

This accepts a string of space separated mnemonic words and returns an
array of seed, mnemonic words, wallet address and spend/view
public/private keys.

    $wallet = $walletManager->wallet_from_mnemonic($mnemonicWords);

### Decode an Integrated Wallet

This accepts an integrated address and returns an array of integrated
wallet address, wallet address, public view key, public spend key and
payment id.

    $wallet = $walletManager->integrated_decode($integrated_wallet);

### Encode an Integrated Wallet

This returns an array of integrated wallet address, wallet address,
public spend key, public view key and payment id.

This can be created with an optional payment id from the public
spend/view keys:

    $iAddress = $walletManager->integrated_encode($public_spend_key, $public_view_key, $payment_id = null);

If you do not have the public keys, the is an
`integrated_encode_address()` function that accepts a wallet address,
decodes this into the public keys and then calls the above function. As
a result, the above is faster if you have the keys available.

    $iAddress = $walletManager->integrated_encode_address($address, $payment_id = null);

### Public Keys From Wallet Address

This accepts a wallet address and decodes it into the public spend and
view keys:

    $wallet = $walletManager>decode_address($address);

This returns an array of wallet address, network bytes, public spend
key and public view key.

### Verify Private Keys

This returns a boolean response based on whether a spend and view key
belong to the same wallet:

    $result = $walletManager->verify_privates($privateSpendKey, $privateViewKey);

### Generate a Payment Id

Generate a cryptographically secure hexadecimal, useful for payment ids:

    $paymentId = $walletManager->generate_payment_id($length);
