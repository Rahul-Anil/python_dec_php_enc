<?php

function encrypt_aes256_CBC($data, $password, $iterations){
    $aes_mode = "AES-256-CBC"; // Currently only AES-256-CBC is supported
    // Create iv
    $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($aes_mode));
    // Create salt
    $salt = openssl_random_pseudo_bytes(16);

    // Create secrety key
    $secret_key = hash_pbkdf2("sha512", $password, $salt, $iterations, 32, true); #bin output

    // Encrypt data
    $et = openssl_encrypt($data, $aes_mode, $secret_key, OPENSSL_RAW_DATA, $iv);

    // Convert values to hex
    $iv_hex = bin2hex($iv);
    $et_hex = bin2hex($et);
    $salt_hex = bin2hex($salt);

    // Create JSON
    $json = json_encode(array("iv" => $iv_hex, "et" => $et_hex, "salt" => $salt_hex));

    // base64 encode JSON
    $json_base64_encode = base64_encode($json);
    return $json_base64_encode;
}

function salt_php_enc_call(){
    $data = "pokemon";
    $password = "garchomp";
    $iterations = 100;
    $json_et = encrypt_aes256_CBC($data, $password, $iterations, $aes_mode);
    print_r("JSON: ".$json_et."\n");
}

salt_php_enc_call();