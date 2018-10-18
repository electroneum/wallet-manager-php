<?php
// Enable debugging
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Load the PHP wallet manager
require_once '../lib/WalletManager.php';
require_once '../lib/Base58.php';
require_once '../lib/Ed25519.php';
require_once '../lib/SHA3.php';
?>
<style>
    form h1 {
        border-bottom: 1px solid #eee;
        margin:0;
        padding: 20px 0;
    }
    form code {
        margin-left: 5px;
        padding: 3px 3px;
        color: #777;
        background-color: #f9f9f9;
        white-space: pre-wrap;
        word-wrap: break-word;
    }
    form #result {
        border-left: 12px solid #eee;
        margin-left: 5px;
        padding: 20px 20px;
        color: #555;
        background-color: #f9f9f9;
        white-space: pre-wrap;
        word-wrap: break-word;
    }
    form div {
        border-bottom: 1px solid #eee;
        padding: 20px 0;
    }
    form label {
        display: inline-block;
        width: 20%;
    }
    form input {
        display: inline-block;
        min-width: 75%;
        font-family: "Courier New";
        padding: 7px 5px;
        border: 1px solid #ddd;
        border-radius: 3px;
    }
</style>

<form method="post">
    <h1>Electroneum PHP Wallet Manager</h1>

    <?php
    // Check for a request.
    if (!empty($_POST)) {
        // Create the Electroneum wallet object.
        $etn = new Electroneum\Wallet\WalletManager();

        echo "<pre id='result'>";

        switch ($_POST['action']) {
            case 'wallet_new':
                print_r($etn->wallet_from_seed());
                break;
            case 'wallet_generate':
                print_r($etn->wallet_from_seed(trim($_POST['wallet_seed'])));
                break;
            case 'wallet_mnemonic':
                print_r($etn->wallet_from_mnemonic(trim($_POST['wallet_mnemonic'])));
                break;
            case 'wallet_integrated_decode':
                print_r($etn->integrated_decode(trim($_POST['wallet_integrated_decode'])));
                break;
            case 'wallet_integrated_encode_address':
                print_r($etn->integrated_encode_address(trim($_POST['wallet_integrated_encode_address_address']), trim($_POST['wallet_integrated_encode_address_payment_id'])));
                break;
            case 'wallet_integrated_encode':
                print_r($etn->integrated_encode(trim($_POST['wallet_integrated_encode_spend']), trim($_POST['wallet_integrated_encode_view']), trim($_POST['wallet_integrated_encode_payment_id'])));
                break;
            case 'wallet_decode':
                print_r($etn->decode_address(@$_POST['wallet_decode']));
                break;
            case 'verify_privates':
                var_dump($etn->verify_privates(@$_POST['verify_privates_spend'], @$_POST['verify_privates_view']));
                break;
            case 'generate_payment_id':
                print_r($etn->generate_payment_id());
                break;
            default:
                echo "ERROR: unknown request.";
        }

        echo "</pre>";
    }
    ?>

    <div>
        <p>
            <strong>Generate ETN Wallet</strong>
            <code>Electroneum\Wallet\WalletManager()->wallet_from_seed()</code>
        </p>
        <button name="action" value="wallet_new">Generate New Wallet</button>
    </div>
    <div>
        <strong>Generate ETN Wallet From Seed</strong>
        <code>Electroneum\Wallet\WalletManager()->wallet_from_seed($seed);</code>
        <p>
            <label for="wallet_seed">Seed (32 chars)</label>
            <input id="wallet_seed" type="text" name="wallet_seed" value="<?=@$_POST['wallet_seed']?>" />
        </p>
        <button name="action" value="wallet_generate">Generate New Wallet From Seed</button>
    </div>
    <div>
        <strong>Generate ETN Wallet From Mnemonic Words</strong>
        <code>Electroneum\Wallet\WalletManager()->wallet_from_mnemonic($words)</code>
        <p>
            <label for="wallet_mnemonic">Mnemonic Words (25 words)</label>
            <input id="wallet_mnemonic" type="text" name="wallet_mnemonic" value="<?=@$_POST['wallet_mnemonic']?>" />
        </p>
        <button name="action" value="wallet_mnemonic">Generate New Wallet From Mnemonic Words</button>
    </div>
    <div>
        <strong>Decode ETN Integrated Wallet</strong>
        <code>Electroneum\Wallet\WalletManager()->integrated_decode($integrated_address)</code>
        <p>
            <label for="wallet_integrated_decode">Integrated Wallet (109 chars)</label>
            <input id="wallet_integrated_decode" type="text" name="wallet_integrated_decode" value="<?=@$_POST['wallet_integrated_decode']?>" />
        </p>
        <button name="action" value="wallet_integrated_decode">Decode Integrated Wallet Address</button>
    </div>
    <div>
        <strong>Encode ETN Integrated Wallet (address)</strong>
        <code>Electroneum\Wallet\WalletManager()->integrated_encode_address($address, $payment_id = null)</code>
        <p>
            <label for="wallet_integrated_encode_address_address">Wallet Address</label>
            <input id="wallet_integrated_encode_address_address" type="text" name="wallet_integrated_encode_address_address" value="<?=@$_POST['wallet_integrated_encode_address_address']?>" />
        </p>
        <p>
            <label for="wallet_integrated_encode_address_payment_id">Payment Id (16 chars) <i>optional</i></label>
            <input id="wallet_integrated_encode_address_payment_id" type="text" name="wallet_integrated_encode_address_payment_id" value="<?=@$_POST['wallet_integrated_encode_address_payment_id']?>" />
        </p>
        <button name="action" value="wallet_integrated_encode_address">Encode Integrated Wallet Address (address)</button>
    </div>
    <div>
        <strong>Encode ETN Integrated Wallet (keys)</strong>
        <code>Electroneum\Wallet\WalletManager()->integrated_encode($public_spend_key, $public_view_key, $payment_id = null)</code>
        <p>
            <label for="wallet_integrated_encode_view">Public View Key (64 chars)</label>
            <input id="wallet_integrated_encode_view" type="text" name="wallet_integrated_encode_view" value="<?=@$_POST['wallet_integrated_encode_view']?>" />
        </p>
        <p>
            <label for="wallet_integrated_encode_spend">Public Spend Key (64 chars)</label>
            <input id="wallet_integrated_encode_spend" type="text" name="wallet_integrated_encode_spend" value="<?=@$_POST['wallet_integrated_encode_spend']?>" />
        </p>
        <p>
            <label for="wallet_integrated_encode_payment_id">Payment Id (16 chars) <i>optional</i></label>
            <input id="wallet_integrated_encode_payment_id" type="text" name="wallet_integrated_encode_payment_id" value="<?=@$_POST['wallet_integrated_encode_payment_id']?>" />
        </p>
        <button name="action" value="wallet_integrated_encode">Encode Integrated Wallet Address</button>
    </div>
    <div>
        <strong>Public Keys From Wallet Address</strong>
        <code>Electroneum\Wallet\WalletManager()->decode_address($address)</code>
        <p>
            <label for="wallet_decode">Integrated Wallet (109 chars)</label>
            <input id="wallet_decode" type="text" name="wallet_decode" value="<?=@$_POST['wallet_decode']?>" />
        </p>
        <button name="action" value="wallet_decode">Public Keys From Wallet Address</button>
    </div>
    <div>
        <strong>Verify Private Keys</strong>
        <code>Electroneum\Wallet\WalletManager()->verify_privates($spend, $view)</code>
        <p>
            <label for="verify_privates_spend">Private Spend Key</label>
            <input id="verify_privates_spend" type="text" name="verify_privates_spend" value="<?=@$_POST['verify_privates_spend']?>" />
        </p>
        <p>
            <label for="verify_privates_view">Private View Key</label>
            <input id="verify_privates_view" type="text" name="verify_privates_view" value="<?=@$_POST['verify_privates_view']?>" />
        </p>
        <button name="action" value="verify_privates">Verify Private Keys</button>
    </div>
    <div>
        <p>
            <strong>Generate Payment Id</strong>
            <code>Electroneum\Wallet\WalletManager()->generate_payment_id($length = 64)</code>
        </p>
        <button name="action" value="generate_payment_id">Generate Payment Id</button>
    </div>
</form>