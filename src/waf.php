<?php
namespace WAF;
class WAF {
	function __construct() {
		$this->IPHeader = "REMOTE_ADDR";
		$this->CookieCheck = true;
		$this->CookieCheckParam = 'username';
		return true;
	}
	function shorten_string($string, $wordsreturned) {  //blocked id值
		$retval = $string;
		$array = explode(" ", $string);
		if (count($array)<=$wordsreturned){
			$retval = $string;
		} else {
			array_splice($array, $wordsreturned);  //$array从0开始插入$wordsreturned
			$retval = implode(" ", $array)." ...";
		}
		return $retval;
	}
	function vulnDetectedHTML($Method, $BadWord, $DisplayName, $TypeVuln) {  //返回界面
		header('HTTP/1.0 403 Forbidden');
		echo '<!DOCTYPE html><html lang="en" xmlns="//www.w3.org/1999/xhtml"><head><style>.app-header,body{text-align:center }.btn,button.btn,input.btn{border:0;outline:0;display:inline-block;vertical-align:middle;border-radius:5em;background-color:#609f43;color:#fff;padding:5px 12px;background-repeat:no-repeat;font-size:14px }.btn:hover{background-color:#58913d }.clearfix:after,.clearfix:before,footer,header,section{display:block }.clearfix:after,.clearfix:before,.row:after{clear:both;content:"" }.clearfix:after,.clearfix:before,.logo-neartext:before,.row:after{content:"" }*{margin:0;padding:0 }html{box-sizing:border-box;font-family:"Open Sans",sans-serif }body,html{height:100% }*,:after,:before{box-sizing:inherit }body{background-color:#e8e8e8;font-size:14px;color:#222;line-height:1.6;padding-bottom:60px }h1{font-size:36px;margin-top:0;line-height:1;margin-bottom:30px }h2{font-size:25px;margin-bottom:10px }a{color:#1e7d9d;text-decoration:none }a:hover{text-decoration:underline }.access-denied .btn:hover,.site-link,footer a{text-decoration:none }.color-green{color:#609f43 }.color-gray{color:grey }hr{border:0;margin:20px auto;border-top:1px #e2e2e2 solid }[class*=icon-circle-]{display:inline-block;width:14px;height:14px;border-radius:50%;margin:-5px 8px 0 0;vertical-align:middle }.icon-circle-red{background-color:#db1802 }#main-container{min-height:100%;position:relative }.app-header{background-color:#333;min-height:50px;padding:0 25px }.app-header .logo{display:block;width:100px;height:24px;float:left; center center no-repeat;background-size:100px 24px;position:absolute;left:0;top:12px }.logo-neartext{display:inline-block;margin-top:3px;color:#fff;font-size:25px;font-weight:600 }.site-link{color:#8a8a8a;font-size:11px;position:absolute;top:15px;right:0 }#recaptcha_image,.box,.captcha,.wrap{position:relative }.wrap{max-width:1090px;margin:auto }.app-content{max-width:580px;margin:40px auto 0;text-align:left;text-align:center }.box{border-radius:10px;background-color:#fff;padding:35px;box-shadow:0 1px 0 0 #d4d4d4;margin:0 4% 35px }#block-details{margin-bottom:35px;margin-top:25px }.row:first-child{border-top:0!important }.row:last-child{border-bottom:0!important }.row:nth-child(even){border:1px solid #e2e2e2;border-left:0;border-right:0;background:#fafafa }.row:after{display:block }.row>div{float:left;padding:12px;word-wrap:break-word }.row>div:first-child{width:15%;font-weight:700 }.row>div:last-child{width:85% }.code-snippet{border:1px solid grey;background-color:#f7f7f7;box-shadow:0 1px 4px 0 rgba(0,0,0,.2);border-radius:8px;padding:18px;margin:30px 0 45px }.medium-text{font-size:16px;clear:both }footer{margin-top:50px;margin-bottom:50px;font-size:13px;color:grey }#privacy-policy{padding-left:25px }@media (max-width:979px){h1{font-size:30px }h2{font-size:20px }.row>div{float:none;width:100%!important }}.captcha{background-color:#fff;width:370px;margin:auto;padding:25px 35px 35px;border-radius:10px;box-shadow:0 1px 0 0 #d4d4d4;border:1px solid #bfbfbf }.captcha-title{text-align:left;margin-bottom:15px;font-size:13px;line-height:1 }table.recaptchatable{margin-left:-14px!important }table#recaptcha_table input[type=text]{height:37px;display:block;width:300px!important;padding:10px!important;border-color:#b8b8b8;font-size:14px;margin-top:20px!important }table#recaptcha_table input[type=text]:focus{background-color:#f9f9f9;border-color:#222;outline:0 }table#recaptcha_table td{display:block;background:0!important;padding:0!important;height:auto!important;position:static!important }#recaptcha_image{border:1px solid #b8b8b8!important;padding:5px;height:60px!important;margin-bottom:25px!important;left:-2px;overflow:hidden;-moz-box-sizing:border-box!important;-webkit-box-sizing:border-box!important;box-sizing:border-box!important }#recaptcha_image img{position:absolute;left:0;top:0 }#recaptcha_reload_btn,#recaptcha_switch_audio_btn,#recaptcha_whatsthis_btn{position:absolute;top:25px }#recaptcha_reload_btn{right:78px }#recaptcha_switch_audio_btn{right:52px }#recaptcha_whatsthis_btn{right:28px }.recaptcha_input_area{margin-left:-7px!important }button.ajax-form{width:300px;cursor:pointer;height:37px;padding:0!important }#recaptcha_privacy{position:absolute!important;top:105px!important;display:block;margin:auto;width:300px;text-align:center }#recaptcha_privacy a{color:#1e7d9d!important }.what-is-firewall{width:100%;padding:35px;background-color:#f7f7f7;-moz-box-sizing:content-box;-webkit-box-sizing:content-box;box-sizing:content-box;margin-left:-35px;margin-bottom:-35px;border-radius:0 0 15px 15px }.access-denied .center{display:table;margin-left:auto;margin-right:auto }.width-max-940{max-width:940px }.access-denied{max-width:none;text-align:left }.access-denied h1{font-size:25px }.access-denied .font-size-xtra{font-size:36px }.access-denied table{margin:25px 0 35px;border-spacing:0;box-shadow:0 1px 0 0 #dfdfdf;border:1px solid #b8b8b8;border-radius:8px;width:100%;background-color:#fff }.access-denied table:first-child{margin-top:0 }.access-denied table:last-child{margin-bottom:0 }.access-denied th{background-color:#ededed;text-align:left;white-space:nowrap }.access-denied th:first-child{border-radius:8px 0 0 }.access-denied th:last-child{border-radius:0 8px 0 0 }.access-denied td{border-top:1px #e2e2e2 solid;vertical-align:top;word-break:break-word }.access-denied td,.access-denied th{padding:12px }.access-denied td:first-child{padding-right:0 }.access-denied tbody tr:first-child td{border-color:#c9c9c9;border-top:0 }.access-denied tbody tr:last-child td:first-child{border-bottom-left-radius:8px }.access-denied tbody tr:last-child td:last-child{border-bottom-right-radius:8px }.access-denied tbody tr:nth-child(2n){background-color:#fafafa }table.property-list td:first-child,table.property-table td:first-child{font-weight:700;width:1%;white-space:nowrap }.overflow-break-all{-ms-word-break:break-all;word-break:break-all }</style><section class="center clearfix"><meta name="viewport" content="width=device-width, initial-scale=1.0" /><title>WAF - Access Denied</title><link href="//fonts.googleapis.com/css?family=Open+Sans:400,300,600,700" rel="stylesheet" type="text/css"></head><body><div id="main-container"><header class="app-header clearfix"><div class="wrap"><span class="logo-neartext">Web Application Firewall</span></div></header><section class="app-content access-denied clearfix"><div class="box center width-max-940"><h1 class="brand-font font-size-xtra no-margin"><i class="icon-circle-red"></i>Access Denied</h1><h1>Block details:</h1><table class="property-table overflow-break-all line-height-16"><tr><td>Your IP:</td><td><span>'. $_SERVER[$this->IPHeader] .'</span></td></tr><tr><td>URL:</td><td><span>'. htmlspecialchars($_SERVER['SERVER_NAME'].$_SERVER['REQUEST_URI'], ENT_QUOTES, 'UTF-8') .'</tr><tr><td>Your Browser: </td><td><span>'.htmlspecialchars($_SERVER['HTTP_USER_AGENT'], ENT_QUOTES, 'UTF-8') . '<tr><td>Block ID:</td><td><span>'.$this->shorten_string(md5($TypeVuln.$Method.$DisplayName.$_SERVER[$this->IPHeader].date('DmY')), 7).'</span></td></tr><tr><td>Block reason:</td><td><span>An attempted ' . htmlentities($TypeVuln) . ' was detected and blocked.</span></td></tr><tr><td>Time:</td><td><span>' . date('Y-m-d H:i:s').'</tr></table></div></section><footer><span>&copy; Design by Freya.</span>';
		die(); // Block request.
	}
	function getArray($Type) {
		switch ($Type) {
			case 'SQL':
				return array(
							"'",
							'´',
							'SELECT FROM',
							'SELECT * FROM',
							'ONION',
							'union',
							'UNION',
							'UDPATE users SET',
							'WHERE username',
							'DROP TABLE',
							'0x50',
							'mid((select',
							'union(((((((',
							'concat(0x',
							'concat(',
							'OR boolean',
							'or HAVING',
							"OR '1", # Famous skid Poc. 
							'0x3c62723e3c62723e3c62723e',
							'0x3c696d67207372633d22',
							'+#1q%0AuNiOn all#qa%0A#%0AsEleCt',
							'unhex(hex(Concat(',
							'Table_schema,0x3e,',
							'0x00', // \0  [This is a zero, not the letter O]
							'0x08', // \b
							'0x09', // \t
							'0x0a', // \n
							'0x0d', // \r
							'0x1a', // \Z
							'0x22', // \"
							'0x25', // \%
							'0x27', // \'
							'0x5c', // \\
							'0x5f'  // \_
							);
				break;
			case 'XSS':
				return array('<img',
						'img>',
						'<image',
						'document.cookie',
						'onerror()',
						'script>',
						'<script',
						'alert(',
						'window.',
						'String.fromCharCode(',
						'javascript:',
						'onmouseover="',
						'<BODY onload',
						'<style',
						'svg onload');
				break;
			
			default:
				return false;
				break;
		}
	}
	function getList($filename){
		$file = fopen($filename, "r")
		or die("Unable to open file");
		$whiltlist = array();
		$array =array();
		if (filesize($filename)>0) {
			$content = fread($file, filesize($filename));
			
			$array = explode("\r\n", $content);
			fclose($file);
		} 
		return $array;
	}

	function arrayFlatten(array $array) {  //把$array多维数组赋给一维数组$flatten
	    $flatten = array();
	    array_walk_recursive($array, function($value) use(&$flatten) {
	        $flatten[] = $value;
	    });
	    return $flatten;
	}
	function sqlCheck($Value, $Method, $DisplayName) { //Displayname 是<input> name 
		// For false alerts.
		$Replace = array("can't" => "cant",
						"don't" => "dont");
		foreach ($Replace as $key => $value_rep) {
			$Value = str_replace($key, $value_rep, $Value); //把value中的key替换为value_rep 其中$Value是method的值
		}
		$BadWords = $this->getList("SQLBlackList.txt");  //得到SQL中的黑名单
		foreach ($BadWords as $BadWord) {
			if (strpos(strtolower($Value), strtolower($BadWord)) !== false) {  //查找badword在$Value中第一次出现的位置，没有找到返回FALSE
				// String contains some Vuln.
				$this->vulnDetectedHTML($Method, $BadWord, $Value, 'SQL Injection');
			}
		}
	}
	function filesCheck($Value,$Method,$DisplayName){
		$string = "";
		foreach ($Value as $value) {
			$string  = $string.$value;
		}
		$flagext = 0;
		$flagmime = 0;
		$WhiteList = $this->getList("FileWhiteList.txt");
		$file_type = $_FILES[$DisplayName]['type'];
		$file_name = $_FILES[$DisplayName]['name'];
		$file_ext = substr($file_name, strrpos($file_name, '.')+1);
		$file_temp = $_FILES[$DisplayName]['tmp_name'];
		$file_mime = mime_content_type($file_temp);
		foreach ($WhiteList as $whiteword) {
			if (strcasecmp($file_ext,$whiteword) ==0) {
				$flagext = 1;
			}
			if (strpos(strtolower($file_mime),strtolower($whiteword))!==false) {
				$flagmime = 1;
			}		
		}
		if ($flagext==1&&$flagmime==1) {
			return $file_ext;
		}else{
			$this->vulnDetectedHTML($Method, $whiteword, $string, 'Upload File Vulnerability');
		}
	}	
	function dealFile($fileType){
		
	}
	function SafeFileUpload($fileType,$DisplayName,$uploadDir){
		$filename = $_FILES[$DisplayName]['name'];
		$file_temp= $_FILES[$Displayname]['tmp_name'];
		$filename =$uploaddir.md5(uniqid().$filename).'.'.$fileType;
		if ($_FILES[$DisplayName]["error"] > 0){
            echo "Error: " . $_FILES[$DisplayName]["error"] . "<br />";
        }
        else{
        	if ($fileType =="jpeg") {
				$tmp = imagecreatefromjpeg($file_tmp);
				imagejpeg($tmp,$tmp_name,50);
			}
			elseif ($fileType =="png") {
				$tmp = imagecreatefrompng($file_tmp);
				imagepng($tmp,$tmp_name,50);
			}
			imagedestroy($tmp);
			move_uploaded_file($file_tmp, $filename);
			if ($fileType == "doc" || $fileType == "docx") {
				$file = fopen($file_temp,"r") or die("Unable to open the file");
				$string = fread($file, filesize($file_temp));
				htmlspecialchars($string);
				fwrite($file_temp, $string);
				fclose($file);
			}
        }
        $tmpdir = substr($file_tmp, 0,strrpos($file_tmp, '/'));
        $tmp_name = substr($file_tmp, strrpos($file_tmp,'/')+1);
        $list = scandir($tmpdir);
        if (in_array($tmp_name, $list,true)) {
            unlink($file_temp);
        }

	}

	function xssCheck($Value, $Method, $DisplayName) {
		// For false alerts.
		$Replace = array("<3" => ":heart:");
		foreach ($Replace as $key => $value_rep) {
			$Value = str_replace($key, $value_rep, $Value);
		}
		$BadWords = $this->getArray('XSS');

		foreach ($BadWords as $BadWord) {
			if (strpos(strtolower($Value), strtolower($BadWord)) !== false) {
			    // String contains some Vuln.

				$this->vulnDetectedHTML($Method, $BadWord, $DisplayName, 'XSS (Cross-Site-Scripting)');
			}
		}
	}
	function is_html($string) {
		return $string != strip_tags($string) ? true:false;  //去除字符串中的html标签

	}
	function santizeString($String) {
		$String = escapeshellarg($String);
		$String = htmlentities($String);
		$XSS = $this->getArray('XSS');
		foreach ($XSS as $replace) {
			$String = str_replace($replace, '', $String);
		}
		$SQL = $this->getArray('SQL');
		foreach ($SQL as $replace) {
			$String = str_replace($replace, '', $String);
		}
		return $String;
	}
	function htmlCheck($value, $Method, $DisplayName) {
		if ($this->is_html(strtolower($value)) !== false) {
			// HTML Detected!
			$this->vulnDetectedHTML($Method, "HTML CHARS", $DisplayName, 'XSS (HTML)');
		}
	}
	function arrayValues($Array) {
		return array_values($Array);
	}
	function checkGET() {
		foreach ($_GET as $key => $value) {//以$key=>$value的形式对$_GET数组进行循环
			if (is_array($value)) {
				$flattened = $this->arrayFlatten($value);
				foreach ($flattened as $sub_key => $sub_value) {
					$this->sqlCheck($sub_value, "_GET", $sub_key);
					$this->xssCheck($sub_value, "_GET", $sub_key);
					$this->htmlCheck($sub_value, "_GET", $sub_key);
				}
			} else {
				$this->sqlCheck($value, "_GET", $key);
				$this->xssCheck($value, "_GET", $key);
				$this->htmlCheck($value, "_GET", $key);
			}
		}
		foreach ($_FILES as $key => $value) {
			//print_r ($value);
			$this->filesCheck($value,"_POST",$key);
		}
	}
	function checkPOST() {
		foreach ($_POST as $key => $value) {
			echo $value;
			if (is_array($value)) {
				$flattened = $this->arrayFlatten($value);
				foreach ($flattened as $sub_key => $sub_value) {
					$this->sqlCheck($sub_value, "_POST", $sub_key);
					$this->xssCheck($sub_value, "_POST", $sub_key);
					$this->htmlCheck($sub_value, "_POST", $sub_key);
				}
			} else {
				$this->sqlCheck($value, "_POST", $key);
				$this->xssCheck($value, "_POST", $key);
				$this->htmlCheck($value, "_POST", $key);

			}
		}
		foreach ($_FILES as $key => $value) {
			//print_r ($value);
			$this->filesCheck($value,"_POST",$key);
		}

	}
	function checkCOOKIE() {
		foreach ($_COOKIE as $key => $value) {
			if (is_array($value)) {
				$flattened = $this->arrayFlatten($value);
				foreach ($flattened as $sub_key => $sub_value) {
					$this->sqlCheck($sub_value, "_COOKIE", $sub_key);
					$this->xssCheck($sub_value, "_COOKIE", $sub_key);
					$this->htmlCheck($sub_value, "_COOKIE", $sub_key);
				}
			} else {
				$this->sqlCheck($value, "_COOKIE", $key);
				$this->xssCheck($value, "_COOKIE", $key);
				$this->htmlCheck($value, "_COOKIE", $key);
			}
		}
	}
	function gua() {
		if (isset($_SERVER['HTTP_USER_AGENT'])) {
			return $_SERVER['HTTP_USER_AGENT'];
		}
		return md5(rand());
	}
	function cutGua($string) {
		$five = substr($string, 0, 4);
		$last = substr($string, -3);
		return md5($five.$last);
	}
	function getCSRF() {
		if (isset($_SESSION['token'])) {
			$token_age = time() - $_SESSION['token_time'];
			if ($token_age <= 300){    /* Less than five minutes has passed. */
				return $_SESSION['token'];
			} else {
				$token =  bin2hex(openssl_random_pseudo_bytes(32));
				$_SESSION['token'] = $token.'asdqwe'.$this->cutGua($this->gua());
				$_SESSION['token_time'] = time();
				return $_SESSION['token'];
			}
		} else {
			$token =  bin2hex(openssl_random_pseudo_bytes(32));
			$_SESSION['token'] = $token.'asdqwe'.$this->cutGua($this->gua());
			$_SESSION['token_time'] = time();
			return $_SESSION['token'];
		}
	}
	function verifyREFERER(){
		$addr = $_SERVER['HTTP_HOST'];
		if (isset($_SERVER['HTTP_REFERER'])) {
			$url = $_SERVER['HTTP_REFERER'];
			$str = str_replace("http://","",$url);
			$strdomain = explode("/",$str);
			$domain = $strdomain[0];
			if (strcmp($domain, $addr)!==0) {
				$file = fopen("BlackIPList.txt","a") or die("Unable to open the file");
				fwrite($file, "\r\n");
				fwrite($file, $this->_SERVER[IPHeader]);
				fclose($file);
				return false;
			}
		}
		return true;
	}
	function verifyCSRF($Value) {
		if (isset($_SESSION['token'])) {
			$token_age = time() - $_SESSION['token_time'];
			if ($token_age <= 300){    /* Less than five minutes has passed. */
				if ($Value == $_SESSION['token']) {
					$Explode = explode('asdqwe', $_SESSION['token']);
					$gua = $Explode[1];
					if ($this->cutGua($this->gua()) == $gua) {
						// Validated, Done!
						unset($_SESSION['token']);
						unset($_SESSION['token_time']);
						return true;
					}
					unset($_SESSION['token']);
					unset($_SESSION['token_time']);
					return false;
				}
			} else {
				return false;
			}
		} else {
			return false;
		}
	}
	function useCloudflare() {
		$this->IPHeader = "HTTP_CF_CONNECTING_IP";
	}
	function useBlazingfast() {
		$this->IPHeader = "X-Real-IP";
	}
	function customIPHeader($String = 'REMOTE_ADDR') {
		$this->IPHeader = $String;
	}
	function antiCookieSteal($listparams = 'username') {
		$this->CookieCheck = true;
		$this->CookieCheckParam = $listparams;
	}
	function cookieCheck() {
		// Check Anti-Cookie steal trick.
		//check ip
		$BlackIPList = $this->getList("BlackIPList.txt");
		foreach ($BlackIPList as $value) {
			if (strcmp($value, $_SERVER[$this->IPHeader])==0) {
				$this->vulnDetectedHTML("_COOKIE",$value,time(),"Suspicious IP");
			}
		}
		if ($this->CookieCheck == true) {
			// Check then.
			if (isset($_SESSION)) { // Session set.
				if (isset($_SESSION[$this->CookieCheckParam])) { // Logged.
					if (!(isset($_SESSION['xWAF-IP']))) {
						$_SESSION['xWAF-IP'] = $_SERVER[$this->IPHeader];
						return true;
					} else {
						if (!($_SESSION['xWAF-IP'] == $_SERVER[$this->IPHeader])) {
							// Changed IP.
							$file = fopen("BlackIPList.txt","a");
							fwrite($file, "\r\n");
							fwrite($file, $_SERVER[$this->IPHeader]);
							fclose($file);
							unset($_SESSION['xWAF-IP']);
							unset($_SESSION);
							@session_destroy();
							@session_start();
							return true;
						}
					}
				}
			}
		}
	}
	function sessionidCheck(){
		session_start();
		$sessionid = session_id();
		$array = $this->getList("sessionIDlog.txt");
		foreach ($array as $value) {
			if (strcmp($value, $sessionid)==0) {
				session_regenerate_id();
				$this->vulnDetectedHTML("_SESSION",$sessionid,time() ,"Session fixation");
			}
			
		}
		$file = fopen("sessionIDlog.txt", "a");
		fwrite($file, "\r\n");
		fwrite($file, $sessionid);
		
		fclose($file);
	}
	function start() {
		@session_start();
		@$this->checkGET();
		@$this->checkPOST();
		@$this->checkCOOKIE();
		if ($this->CookieCheck == true) {
			$this->cookieCheck();
		}
	}

}
?>
