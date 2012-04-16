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
	private $box, $initBox, $i, $j, $drop;

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
	
	public function crypt($str, $init = true){
		if($init !== false){
			$this->initPRGA(); //Allow chaining
		}
		$len = strlen($str);
		$res = "";
		for($i = 0; $i < $len; ++$i){
			$res .= chr(ord($str{$i}) ^ $this->PRGA($i));
		}
		return $res;
	}
	
	public function IV($IV){
		$this->initBox = $this->KSA($IV);
		$this->initPRGA();
	}
	
	public function nonce($nonce){
		
		$len = strlen($nonce);
		$j = 0;
		$h = 0;
		$box = $this->initBox;
		
		for($i = 0; $i < ($len * 256); ++$i){
			$h = ($box[($i + 1 + ord($nonce{$i % $len}) + $h) % 256][($h + ord($nonce{($i + $h + $j) % $len})) % 256] + $h + 1) % 256;
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
	
	protected function initPRGA(){
		$this->i = 0;
		$this->j = 0;
		$this->h = 0;
		$this->ch = 0;
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
		$len = strlen($IV);
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
			for($j = 0; $j < 256; ++$j){
				$h = ($h + $box[($h + $j) % 256][($h + $i + 1) % 256] + ord($IV{(($i * 256) + $j) % $len})) % 256;
				self::swap($box[$i][($j + 1) % 256], $box[$h][$j]);
				self::swap($box[$i][$h], $box[$j][$h]);
				self::swap($box[$i][$j], $box[$h][$i]);
			}
			self::swap($box[($i + $h) % 256], $box[($h + 1) % 256]);
		}
		
		$j = 0;
		$h = 0;
		for($i = 0; $i < $len; ++$i){
			$h = ($box[($i + 1 + (ord($IV{$i}) & 0xf0) + $h) % 256][($h + (ord($IV{($i + $h + $j) % $len}) & 0xf0)) % 256] + $h + 1) % 256;
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
