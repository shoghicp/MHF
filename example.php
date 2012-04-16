<?php

include_once("MHF.class.php");

//Encryption / Decryption example

$key = "high_secret_key";
$nonce = time(); //A non-secure nonce (but it isn't very important)

$MHF = new MHF($key, $nonce); // You could also ommit the nonce
echo "Key => ",$key,PHP_EOL;
echo "Nonce => ",$nonce,PHP_EOL;

$encrypted = base64_encode($MHF->crypt("A nasty text"));
echo "Encrypted text (base64) => ",$encrypted,PHP_EOL;

$decrypted = $MHF->crypt(base64_decode($encrypted));
echo "Decrypted text => ",$decrypted,PHP_EOL,PHP_EOL;


//Hashing example
$str = "passwordTOhash";
$MHF = new MHF($str); //Nonce optional, it could be the username
echo "Plaintext => ",$str,PHP_EOL;
echo "Hash => ",$MHF->hash(32),PHP_EOL;


?>
