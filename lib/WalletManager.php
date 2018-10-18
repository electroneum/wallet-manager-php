<?php

namespace Electroneum\Wallet;

use Exception;

class WalletManager
{
    protected $wallet_prefix = 'e28c01';
    protected $wallet_integrated_prefix = 'e38c01';
    protected $payment_id_length = 64;
    protected $payment_id_length_integrated = 16;
    private $ed25519;
    private $base58;
    private $mnemonic_language;

    public function __construct($lang = 'en')
    {
        $this->ed25519 = new Ed25519();
        $this->base58 = new Base58();
        $this->mnemonic_language = $lang;
    }

    /*
     * @param string Hex encoded string of the data to hash
     * @return string Hex encoded string of the hashed data
     *
     */
    public function keccak_256($message)
    {
        $keccak256 = SHA3::init (SHA3::KECCAK_256);
        $keccak256->absorb (hex2bin($message));
        return bin2hex($keccak256->squeeze (32)) ;
    }

    /*
     * @return string A hex encoded string of 32 random bytes
     *
     */
    public function gen_new_hex_seed()
    {
        $bytes = random_bytes(32);
        return bin2hex($bytes);
    }

    public function sc_reduce($input)
    {
        $integer = $this->ed25519->decodeint(hex2bin($input));

        $modulo = bcmod($integer , $this->ed25519->l);

        $result = bin2hex($this->ed25519->encodeint($modulo));
        return $result;
    }

    /*
     * Hs in the cryptonote white paper
     *
     * @param string Hex encoded data to hash
     *
     * @return string A 32 byte encoded integer
     */
    public function hash_to_scalar($data)
    {
        $hash = $this->keccak_256($data);
        $scalar = $this->sc_reduce($hash);
        return $scalar;
    }

    /*
     * Derive a deterministic private view key from a private spend key
     * @param string A private spend key represented as a 32 byte hex string
     *
     * @return string A deterministic private view key represented as a 32 byte hex string
     */
    public function derive_viewKey($spendKey)
    {
        return $this->hash_to_scalar($spendKey);
    }

    /*
     * Generate a pair of random private keys
     *
     * @param string A hex string to be used as a seed (this should be random)
     *
     * @return array An array containing a private spend key and a deterministic view key
     */
    public function gen_private_keys($seed)
    {
        $spendKey = $this->sc_reduce($seed);
        $viewKey = $this->derive_viewKey($spendKey);
        $result = array("spendKey" => $spendKey, "viewKey" => $viewKey);

        return $result;
    }

    /*
     * Get a public key from a private key on the ed25519 curve
     *
     * @param string a 32 byte hex encoded private key
     *
     * @return string a 32 byte hex encoding of a point on the curve to be used as a public key
     */
    public function pk_from_sk($privKey)
    {
        $keyInt = $this->ed25519->decodeint(hex2bin($privKey));
        $aG = $this->ed25519->scalarmult_base($keyInt);
        return bin2hex($this->ed25519->encodepoint($aG));
    }

    /*
     * Generate key derivation
     *
     * @param string a 32 byte hex encoding of a point on the ed25519 curve used as a public key
     * @param string a 32 byte hex encoded private key
     *
     * @return string The hex encoded key derivation
     */
    public function gen_key_derivation($public, $private)
    {
        $point = $this->ed25519->scalarmult($this->ed25519->decodepoint(hex2bin($public)), $this->ed25519->decodeint(hex2bin($private)));
        $res = $this->ed25519->scalarmult($point, 8);
        return bin2hex($this->ed25519->encodepoint($res));
    }

    public function encode_varint($data)
    {
        if ($data < 0x80)
        {
            return bin2hex(pack('C', $data));
        }

        $encodedBytes = [];
        while ($data > 0)
        {
            $encodedBytes[] = 0x80 | ($data & 0x7f);
            $data >>= 7;
        }

        $encodedBytes[count($encodedBytes)-1] &= 0x7f;
        $bytes = call_user_func_array('pack', array_merge(array('C*'), $encodedBytes));;
        return bin2hex($bytes);
    }

    public function derivation_to_scalar($der, $index)
    {
        $encoded = $this->encode_varint($index);
        $data = $der . $encoded;
        return $this->hash_to_scalar($data);
    }

    // this is a one way function used for both encrypting and decrypting 8 byte payment IDs
    public function stealth_payment_id($payment_id, $tx_pub_key, $viewkey)
    {
        $der = $this->gen_key_derivation($tx_pub_key, $viewkey);
        $data = $der . '8d';
        $hash = $this->keccak_256($data);
        $key = substr($hash, 0, 16);
        $result = bin2hex(pack('H*',$payment_id) ^ pack('H*',$key));
        return $result;
    }

    // takes transaction extra field as hex string and returns transaction public key 'R' as hex string
    public function txpub_from_extra($extra)
    {
        $parsed = array_map("hexdec", str_split($extra, 2));

        if($parsed[0] == 1)
        {
            return substr($extra, 2, 64);
        }

        if($parsed[0] == 2)
        {
            if($parsed[0] == 2 || $parsed[2] == 1)
            {
                $offset = (($parsed[1] + 2) *2) + 2;
                return substr($extra, (($parsed[1] + 2) *2) + 2, 64);
            }
        }
    }

    public function derive_public_key($der, $index, $pub)
    {
        $scalar = $this->derivation_to_scalar($der, $index);
        $sG = $this->ed25519->scalarmult_base($this->ed25519->decodeint(hex2bin($scalar)));
        $pubPoint = $this->ed25519->decodepoint(hex2bin($pub));
        $key = $this->ed25519->encodepoint($this->ed25519->edwards($pubPoint, $sG));
        return bin2hex($key);
    }

    /*
     * Perform the calculation P = P' as described in the cryptonote whitepaper
     *
     * @param string 32 byte transaction public key R
     * @param string 32 byte receiver private view key a
     * @param string 32 byte receiver public spend key B
     * @param int output index
     * @param string output you want to check against P
     */
    public function is_output_mine($txPublic, $privViewkey, $publicSpendkey, $index, $P)
    {
        $derivation = $this->gen_key_derivation($txPublic, $privViewkey);
        $Pprime = $this->derive_public_key($derivation, $index, $publicSpendkey);

        if($P == $Pprime)
        {
            return true;
        }
        else
            return false;
    }

    /*
     * Create a valid base58 encoded Monero address from public keys
     *
     * @param string Public spend key
     * @param string Public view key
     *
     * @return string Base58 encoded Monero address
     */
    public function encode_address($pSpendKey, $pViewKey)
    {
        // Validate the spend key length.
        if (strlen($pSpendKey) !== 64) {
            throw new Exception('Error: Incorrect public spend key length');
        }

        // Validate the view key length.
        if (strlen($pViewKey) !== 64) {
            throw new Exception('Error: Incorrect public view key length');
        }

        $preAddr = $this->wallet_prefix . $pSpendKey . $pViewKey;
        $checksum = $this->keccak_256($preAddr);
        $data = $preAddr . substr($checksum, 0, 8);
        $encoded = $this->base58->encode($data);

        // Validate the address length.
        if (strlen($encoded) !== 98) {
            throw new Exception('Error: Incorrect wallet address length');
        }

        return $encoded;
    }

    public function verify_checksum($address)
    {
        $decoded = $this->base58->decode($address);
        $checksum = substr($decoded, -8);
        $checksum_hash = $this->keccak_256(substr($decoded, 0, -8));
        $calculated = substr($checksum_hash, 0, 8);
        if($checksum == $calculated){
            return true;
        }
        else
            return false;
    }

    /*
     * Generate a random payment id
     *
     * @return string Payment id
     */
    public function generate_payment_id($length = null)
    {
        if (empty($length)) {
            $length = $this->payment_id_length;
        }

        return bin2hex(random_bytes($length / 2));
    }

    /*
     * Decode a base58 encoded Monero address
     *
     * @param string A base58 encoded Monero address
     *
     * @return array An array containing the Address network byte, public spend key, and public view key
     */
    public function decode_address($address)
    {
        if(!$this->verify_checksum($address)){
            throw new Exception("Error: invalid checksum");
        }

        $decoded = $this->base58->decode($address);
        $network_byte = substr($decoded, 0, 6);
        $public_spendKey = substr($decoded, 6, 64);
        $public_viewKey = substr($decoded, 70, 64);
        $checksum = substr($decoded, -8);

        return array(
            "address" => $address,
            "networkByte" => $network_byte,
            "spendKey" => $public_spendKey,
            "viewKey" => $public_viewKey,
        );
    }

    /*
     * Get an integrated address from wallet address and a payment id
     *
     * @param string A 109 hex character wallet address
     * @param string An 8 byte hex string to use as a payment id
     */
    public function integrated_encode_address($address, $payment_id = null)
    {
        // Validate wallet address length.
        if (strlen($address) !== 98) {
            throw new Exception('Error: Invalid wallet address length');
        }

        // Generate payment id if required.
        if (empty($payment_id)) {
            $payment_id = $this->generate_payment_id($this->payment_id_length_integrated);
        }

        // Validate payment id length.
        if (strlen($payment_id) !== $this->payment_id_length_integrated) {
            throw new Exception('Error: Invalid integrated payment id length');
        }

        // Get the public keys from the wallet address.
        $keys = $this->decode_address($address);

        return $this->integrated_encode($keys['spendKey'], $keys['viewKey'], $payment_id);
    }

    /*
     * Get an integrated address from public keys and a payment id
     *
     * @param string A 32 byte hex encoded public spend key
     * @param string A 32 byte hex encoded public view key
     * @param string An 8 byte hex string to use as a payment id
     */
    public function integrated_encode($public_spendkey, $public_viewkey, $payment_id = null)
    {
        // Generate payment id if required.
        if (empty($payment_id)) {
            $payment_id = $this->generate_payment_id($this->payment_id_length_integrated);
        }

        // Validate public spend key length.
        if (strlen($public_spendkey) !== 64) {
            throw new Exception('Error: Invalid public spend key length');
        }

        // Validate public view key length.
        if (strlen($public_viewkey) !== 64) {
            throw new Exception('Error: Invalid public view key length');
        }

        // Validate payment id length.
        if (strlen($payment_id) !== $this->payment_id_length_integrated) {
            throw new Exception('Error: Invalid payment id length');
        }

        // 0x13 is the mainnet network byte for integrated addresses
        $data = $this->wallet_integrated_prefix . $public_spendkey . $public_viewkey . $payment_id;
        $checksum = substr($this->keccak_256($data), 0, 8);
        $iAddress = $this->base58->encode($data.$checksum);
        $address = $this->encode_address($public_spendkey, $public_viewkey);

        return array(
            'integrated_address' => $iAddress,
            'address' => $address,
            'view_public' => $public_viewkey,
            'spend_public' => $public_spendkey,
            'payment_id' => $payment_id,
        );
    }

    /*
     * Decode an integrated address
     *
     * @param string An integrated wallet address
     */
    public function integrated_decode($iAddress)
    {
        // Validate integrated address length.
        if (strlen($iAddress) !== 109) {
            throw new Exception('Error: Invalid integrated address length');
        }

        // Base58 decode the address.
        $data = $this->base58->decode($iAddress);
        $data = substr($data, 0, -8);

        // Split into the prefix, spend key, view key & payment_id.
        $prefix = substr($data, 0, 6);
        $key_spend_public = substr($data, 6, 64);
        $key_view_public = substr($data, 70, 64);
        $payment_id = substr($data, 134);
        $address = $this->encode_address($key_spend_public, $key_view_public);

        // Check the prefix is correct.
        if ($prefix !== $this->wallet_integrated_prefix) {
            throw new Exception("Error: Invalid prefix");
        }

        // Validate integrated address length.
        if (strlen($payment_id) !== $this->payment_id_length_integrated) {
            throw new Exception('Error: Invalid payment id length');
        }

        return array(
            'integrated_address' => $iAddress,
            'address' => $address,
            'view_public' => $key_view_public,
            'spend_public' => $key_spend_public,
            'payment_id' => $payment_id,
        );
    }

    /*
     * Generate a Monero address from seed
     *
     * @param string Hex string to use as seed
     *
     * @return string A base58 encoded Monero address
     */
    public function wallet_from_seed($hex_seed = null, $ret_mnemonic = true)
    {
        if ($hex_seed === null) {
            $hex_seed = $this->gen_new_hex_seed();
        }

        // Validate the seed length.
        if (strlen($hex_seed) !== 64) {
            throw new Exception('Error: Incorrect seed length');
        }

        $private_keys = $this->gen_private_keys($hex_seed);
        $private_viewKey = $private_keys["viewKey"];
        $private_spendKey = $private_keys["spendKey"];

        $public_spendKey = $this->pk_from_sk($private_spendKey);
        $public_viewKey = $this->pk_from_sk($private_viewKey);

        $address = $this->encode_address($public_spendKey, $public_viewKey);

        $mnemonic = $ret_mnemonic === true ? $this->mn_encode($hex_seed) : null;

        return array(
            'seed' => $hex_seed,
            'mnemonic' => $mnemonic,
            'address' => $address,
            'view_private' => $private_viewKey,
            'view_public' => $public_viewKey,
            'spend_private' => $private_spendKey,
            'spend_public' => $public_spendKey,
        );
    }

    /*
     * Create a wallet from mnemonic words
     *
     * @param string $mnemonic
     * @return array
     */
    public function wallet_from_mnemonic($mnemonic)
    {
        $seed = $this->mn_decode($mnemonic);
        return $this->wallet_from_seed($seed);
    }

    /*
     * Convert a seed to mnemonic words
     *
     * @param string $seed
     * @return string
     */
    public function mn_encode($seed = null)
    {
        // Get the mnemonic word list for the given language.
        $words = json_decode(file_get_contents(__DIR__ . '/mnemonic.json'), true);
        $words = $words[$this->mnemonic_language];

        // Default mnemonic words to English if unknown language was supplied.
        if (empty($words)) {
            $words = $words['en'];
        }

        $wordsLen = count($words['words']);

        // Generate a random seed if required.
        if ($seed === null) {
            $seed = $this->gen_new_hex_seed();
        }

        $swapped = $seed;
        for ($i = 0; $i < strlen($seed); $i += 8) {
            $swapped = substr($swapped, 0, $i) . $this->mn_swap_endian_4byte(substr($swapped, $i, 8)) . substr($swapped, $i + 8);
        }

        $result = [];
        for ($i = 0; $i < strlen($swapped); $i += 8)
        {
            $x = intval(substr($swapped, $i, 8), 16);
            $w1 = $x % $wordsLen;
            $w2 = (floor($x / $wordsLen) + $w1) % $wordsLen;
            $w3 = (floor(floor($x / $wordsLen) / $wordsLen) + $w2) % $wordsLen;
            $result = array_merge($result, [$words['words'][$w1], $words['words'][$w2], $words['words'][$w3]]);
        }

        if ($words['prefix_len'] > 0) {
            $result[] = $result[$this->mn_get_checksum_index($result, $words['prefix_len'])];
        }

        return implode(' ', $result);
    }

    /*
     * Convert mnemonic words to a hexadecimal seed
     *
     * @param string $mnemonic
     * @return string
     */
    public function mn_decode($mnemonic)
    {
        // Get the mnemonic word list for the given language.
        $words = json_decode(file_get_contents(__DIR__ . '/mnemonic.json'), true);
        $words = $words[$this->mnemonic_language];
        $wordsLen = count($words['words']);

        // Split the mnemonic string into an array.
        $mnemonicList = explode(' ', $mnemonic);

        // Validate mnemonic word length.
        if (count($mnemonicList) < 12) {
            throw new Exception('Error: Too few mnemonic words');
        }

        // Validate mnemonic word length number.
        if ($words['prefix_len'] === 0 && count($mnemonicList) % 3 !== 0) {
            throw new Exception('Error: Too few mnemonic words');
        }
        if ($words['prefix_len'] > 0 && count($mnemonicList) % 3 === 2) {
            throw new Exception('Error: Too few mnemonic words');
        }
        if ($words['prefix_len'] > 0 && count($mnemonicList) % 3 === 0) {
            throw new Exception('Error: Last mnemonic word is missing');
        }

        // Get the checksum if required.
        $checksum_word = '';
        if ($words['prefix_len'] > 0) {
            $checksum_word = array_pop($mnemonicList);
        }

        // Build the seed from the mnemonic word list.
        $result = '';
        for ($i = 0; $i < count($mnemonicList); $i += 3) {
            $w1 = array_search($mnemonicList[$i], $words['words']);
            $w2 = array_search($mnemonicList[$i + 1], $words['words']);
            $w3 = array_search($mnemonicList[$i + 2], $words['words']);

            $x = $w1 + $wordsLen * ((($wordsLen - $w1) + $w2) % $wordsLen) + $wordsLen * $wordsLen * ((($wordsLen - $w2) + $w3) % $wordsLen);
            $result .= $this->mn_swap_endian_4byte(substr('0000000' . dechex($x), -8));
        }

        // Verify the checksum.
        if (!empty($checksum_word)) {
            $checksum_index = $this->mn_get_checksum_index($mnemonicList, $words['prefix_len']);

            if (substr($mnemonicList[$checksum_index], 0, $words['prefix_len']) !== substr($checksum_word, 0, $words['prefix_len'])) {
                throw new Exception('Error: Private key cannot be verified');
            }
        }

        return $result;
    }

    public function mn_swap_endian_4byte($str)
    {
        return substr($str, 6, 2) . substr($str, 4, 2) . substr($str, 2, 2) . substr($str, 0, 2);
    }

    public function mn_get_checksum_index($words, $prefix_len)
    {
        $trimmed = '';
        for ($i = 0; $i < count($words); $i++) {
            $trimmed .= substr($words[$i], 0, $prefix_len);
        }
        $checksum = crc32($trimmed);

        return $checksum % count($words);
    }

    public function verify_privates($spend, $view)
    {
        // Verify spend key length.
        if (strlen($spend) !== 64) {
            throw new Exception('Error: Invalid private spend key length');
        }

        // Verify view key length.
        if (strlen($view) !== 64) {
            throw new Exception('Error: Invalid private view key length');
        }

        if ($view === $this->derive_viewKey($spend)) {
            return true;
        } else {
            return false;
        }
    }
}
