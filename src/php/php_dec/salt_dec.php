<?php

function decrypt_aes256_CBC($data, $password, $iterations){
    $dt = false;
    $aes_mode = "AES-256-CBC"; // Currently only AES-256-CBC is supported
    $json_decoded = json_decode(base64_decode($data), true);

    // Check if the JSON that has been decoded is not null
    if (is_null($json_decoded)) {
        print_r("Error: JSON is not valid");
        return $dt;
    }

    // Check if all the values are present in the JSON
    if(!isset($json_decoded["iv"]) || !isset($json_decoded["et"]) || !isset($json_decoded["salt"])){
        print_r("Error: JSON is missing values");
        return $dt;
    }

    // Convert hex values to bin 
    $iv = hex2bin($json_decoded["iv"]);
    $salt = hex2bin($json_decoded["salt"]);
    $et = hex2bin($json_decoded["et"]);

    // Generate secret key
    $secret_key = hash_pbkdf2("sha512", $password, $salt, $iterations, 32, true);

    // Decrypt data
    $dt = openssl_decrypt($et, $aes_mode, $secret_key, OPENSSL_RAW_DATA, $iv);
    return $dt;
}

function salt_php_dec_call(){
    $data = "eyJpdiI6IjEyZDlhYTY5YzM1MjU4ZDZiNGZhNTE3NGZkMTg3MDJjIiwiZXQiOiJmMTBhY2NmZmI4NjI3MDc4NDVmNjZlMWI1MjEyMDVjMCIsInNhbHQiOiJhZGFmMmEzNjllMDQ0YmFhNWE3Mjc0NjAxNDUxMjIxNyJ9";
    $password = "garchomp";
    $iterations = 100;
    $plaintext = decrypt_aes256_CBC($data, $password, $iterations);
    print_r("plaintext: ".$plaintext."\n");
}

salt_php_dec_call();