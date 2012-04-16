<?php

include_once("MHF.class.php");

$MHF = new MHF("thisismypassword");

$fp = fopen($argv[1], "r");
$fw = fopen($argv[1].".bin", "w");
while(!feof($fp)){
	fwrite($fw,$MHF->crypt(fread($fp, 4096), false));
}
fclose($fp);
fclose($fw);

