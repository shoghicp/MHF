<?php

include_once("MHF.class.php");
$key = "high_secret_key";
$str = "passwordTOhash";
$nonce = "publicNonce";//time(); //A non-secure nonce (but it isn't very important)

//Encryption / Decryption example

$MHF = new MHF($key, $nonce); // You could also ommit the nonce
echo "Key => ",$key,PHP_EOL;
echo "Nonce => ",$nonce,PHP_EOL;

$encrypted = base64_encode($MHF->crypt("A nasty text"));
echo "Encrypted text (base64) => ",$encrypted,PHP_EOL;

$decrypted = $MHF->crypt(base64_decode($encrypted));
echo "Decrypted text => ",$decrypted,PHP_EOL,PHP_EOL;


//Encryption / Decryption example (malleability denegation)

$MHF = new MHF($key, $nonce);

$encrypted = base64_encode($MHF->encrypt("Another nasty text"));
echo "Encrypted text (base64) [mall. deny] => ",$encrypted,PHP_EOL;

$decrypted = $MHF->decrypt(base64_decode($encrypted));
echo "Decrypted text [mall. deny] => ",$decrypted,PHP_EOL,PHP_EOL;

$encrypted{7} = chr(1+ord($encrypted{7})); //Change a byte

//Hashing example
$MHF = new MHF($str); //Nonce optional, it could be the username
echo "Plaintext => ",$str,PHP_EOL;
echo "Hash => ",$MHF->hash(32),PHP_EOL;


?>
