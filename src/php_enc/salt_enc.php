<?php

function salt_php_enc($data, $password, $iterations, $aes_mode){
    print_r("SALT ENC\n");

    // Create iv
    $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($aes_mode));
    // Create salt
    $salt = openssl_random_pseudo_bytes(16);

    // Create secrety key
    $secret_key = hash_pbkdf2("sha512", $password, $salt, $iterations, 32, true); #bin output
    print_r("secretkey: ".$secret_key."\n"); #bin 
    print_r("secretkey hex: ".bin2hex($secret_key)."\n"); #hex representation
    print_r("byte length of secret key: ".strlen($secret_key)."\n");

    // Encrypt data
    $et = openssl_encrypt($data, $aes_mode, $secret_key, OPENSSL_RAW_DATA, $iv);

    // Convert values to hex
    $iv_hex = bin2hex($iv);
    $et_hex = bin2hex($et);
    $salt_hex = bin2hex($salt);

    // Create JSON
    $json = json_encode(array("iv" => $iv_hex, "et" => $et_hex, "salt" => $salt_hex));
    print_r("json: ".$json."\n");
    $json_base64_encode = base64_encode($json);
    return $json_base64_encode;
}

function salt_php_enc_call(){
    $data = "pokemon";
    $password = "garchomp";
    $iterations = 100;
    $aes_mode = "AES-256-CBC";
    $json_et = salt_php_enc($data, $password, $iterations, $aes_mode);
    print_r("JSON: ".$json_et."\n");
}

salt_php_enc_call();