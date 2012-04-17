<?php

/*
 * MHF - Multi Hash Function
 *  by @shoghicp
 * 
 * Based on RC4 (and deleting some of their weakness),
 * this stream cipher allows any key size, and the first
 * portion of the keystream is discarded.
 * An optional nonce can be added to the input of the algorithm.
 * Also allows to create hashes of arbitrary lenght (but lenght
 * must be divisible by 2)
 * Now denegates malleability
 * 
 * 
 * WARNING
 * This is a work in progress, the algorithm could change to improve security
 * 
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * 
 */


class MHF{
	private $box, $initBox, $i, $j, $drop, $count;

	function __construct($IV, $nonce = null){
		$this->drop = 512;
		$this->IV($IV);
		if($nonce !== null){
			$this->nonce($nonce);
		}
	}
	
	public function hash($hexlen = 64, $init = true){
		$hexlen = abs(intval($hexlen));
		if($hexlen % 2 == 1){
			return false;
		}
		if($init !== false){
			$this->initPRGA(); //Allow chaining
		}
		
		$ret = "";
		for($i = 0; $i < $hexlen; $i += 2){
			$ret .= str_pad(dechex($this->PRGA($i)), 2, "0", STR_PAD_LEFT);
			for($j = 0; $j < 256; ++$j){
				$this->PRGA($i * 256 + $j);
			}
		}
		return $ret;
	}

	public function encrypt($str){ //Encryption, denegates malleability
		$this->initPRGA();
		$str = array_map("ord", str_split($str, 1));		
		$len = count($str);
		$last = 0;

		for($i = 0; $i < $len; ++$i){
			$ch = $str[$i];
			$str[$i] = $ch ^ $this->PRGA($i + $last); //Chain last byte
			$last = $ch;
		}

		return implode(array_map("chr", $str));
	}
	
	public function decrypt($str){ //Decryption, denegates malleability
		$this->initPRGA();
		$str = array_map("ord", str_split($str, 1));		
		$len = count($str);
		$last = 0;

		for($i = 0; $i < $len; ++$i){
			$last = $str[$i] ^ $this->PRGA($i + $last); //Chain last byte
			$str[$i] = $last;
		}

		return implode(array_map("chr", $str));
	}
	
	public function crypt($str, $init = true){ //Two-Way encrypt/decrypt same function
		if($init !== false){
			$this->initPRGA(); //Allow chaining
		}
		$str = array_map("ord", str_split($str, 1));		
		$len = count($str);
		
		for($i = 0; $i < $len; ++$i){
			$str[$i] = $str[$i] ^ $this->PRGA($i + $this->count);
		}
		if($init === false){
			$this->count += $len;
		}
		return implode(array_map("chr", $str));
	}
	
	public function IV($IV){
		$this->initBox = $this->KSA($IV);
		$this->initPRGA();
	}
	
	public function nonce($nonce){
		
		$nonce = array_map("ord", str_split($nonce, 1));
		$len = count($nonce);
		$j = 0;
		$h = 0;
		$box = $this->initBox;
		
		for($i = 0; $i < ($len * 256); ++$i){
			$h = ($box[($i + 1 + $nonce[$i % $len] + $h) % 256][($h + $nonce[($i + $h + $j) % $len]) % 256] + $h + 1) % 256;
			$j = ($h + $i + $j + 1) % 256;
			self::swap($box[$h][$j], $box[$j][$i]);
			self::swap($box[$i % 256], $box[($h + $j) % 256]);		
		}
		$this->initBox = $box;
		$this->initPRGA();
	}
	
	public function drop($drop){
		$this->drop = abs(intval($drop));
		$this->initPRGA();
	}	
	
	public function initPRGA(){
		$this->i = 0;
		$this->j = 0;
		$this->h = 0;
		$this->ch = 0;
		$this->count = 0;
		$this->box = $this->initBox;
		$this->dropPRGA($this->drop);
	}
	
	private function dropPRGA($count){
		for($i = 0; $i < $count; ++$i){
			$this->PRGA($this->PRGA($i));
		}
	}

	public static function swap(&$a, &$b){
		$c = $a;
		$a = $b;
		$b = $c;
	}

	private function KSA($IV){
		$IV = array_map("ord", str_split($IV, 1));
		$len = count($IV);
		if($len == 0){ //Empty key
			$IV = "\x00";
			$len = 1;
		}
		$box = array();
		
		for($i = 0; $i < 256; ++$i){
			$box[$i] = array();
			for($j = 0; $j < 256; ++$j){
				$box[$i][$j] = $j;
			}
		}
		
		$h = 0;
		for($i = 0; $i < 256; ++$i){
			for($j = 0; $j < (64 + $h); ++$j){
				$h = ($h + $box[($h + $j) % 256][($h + $i + 1) % 256] + $IV[(($i * 256) + $j) % $len]) % 256;
				self::swap($box[$i][($j + 1) % 256], $box[$h][$j]);
				self::swap($box[$i][$h], $box[$j][$h]);
				self::swap($box[$i][$j], $box[$h][$i]);
			}
			self::swap($box[($i + $h) % 256], $box[($h + 1) % 256]);
		}
		
		$j = 0;
		$h = 0;
		for($i = 0; $i < $len; ++$i){
			$h = ($box[($i + 1 + ($IV[$i] & 0xf0) + $h) % 256][($h + ($IV[($i + $h + $j) % $len] & 0xf0)) % 256] + $h + 1) % 256;
			$j = ($h + $i + $j + 1) % 256;
			self::swap($box[$h][$j], $box[$j][$i]);
			self::swap($box[$h][$i], $box[$j][$h]);		
		}
		return $box;
	}
	
	protected function PRGA($ch){
		if($ch === false){
			return 0;
		}
		
		$i = $this->i;
		$j = $this->j;
		$h = $this->h;
		$ch = ($this->ch + $ch) % 256;
		
		$i = ($i + 1) % 256;
		$j = ($j + $this->box[($i + $ch) % 256][$j] + $ch) % 256;
		$h = ($h + $this->box[$j][($i + $ch) % 256]) % 256;
		self::swap($this->box[$h][$j], $this->box[$i][$h]);
		self::swap($this->box[$i][$j], $this->box[$h][$i]);
		
		$this->i = $i;
		$this->j = $j;
		$this->h = $h;
		$this->ch = $ch;
		$r1 = $this->box[($this->box[$i][$j] + $this->box[$h][$i]) % 256][($this->box[$j][$i] + $this->box[$i][$h]) % 256];
		$r2 = $this->box[($this->box[$j][$i] + $this->box[$i][$h] + $r1) % 256][($this->box[$i][$j] + $this->box[$h][$i] + $r1) % 256];
		return $r1 ^ $r2;
	}

}

?>
