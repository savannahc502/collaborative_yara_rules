rule is_PHP_GZ_Inflate {
	meta:
		description = "Detects the use of the PHP gzinflate function"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
	    $func = "gzinflate("
	condition:
      $func

}
