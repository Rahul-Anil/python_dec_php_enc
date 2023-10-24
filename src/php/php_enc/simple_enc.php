<?php

function simple_php_enc($data, $key, $aes_mode) {
    print_r("SIMPLE ENCRYPTION\n");
    $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($aes_mode));
    $et = openssl_encrypt($data, $aes_mode, $key, OPENSSL_RAW_DATA, $iv);

    $iv_hex = bin2hex($iv);
    $et_hex = bin2hex($et);
    $json = json_encode(array("iv" => $iv_hex, "et" => $et_hex));
    return $json;
}

function call_simple_php_enc(){
    $data = "pokemon";
    $key = "garchomp";
    $aes_mode = "AES-256-CBC";
    $hex_key = bin2hex($key);
    $hex_key_pad = str_pad($hex_key, 64, "00");
    $bin_key = hex2bin($hex_key_pad);
    $json_et = simple_php_enc($data, $bin_key, $aes_mode);
    print_r("JSON: ".$json_et."\n");
}

call_simple_php_enc();