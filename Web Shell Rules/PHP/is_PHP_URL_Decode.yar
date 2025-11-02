rule is_PHP_URL_Decode {
	meta:
		description = "Detects the use of the PHP urldecode function"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
	    $func = "urldecode("
	condition:
      $func

}
