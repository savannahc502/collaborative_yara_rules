rule is_PHP_Popen {
	meta:
		description = "Detects the use of the PHP popen function"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
	    $func = "popen("
	condition:
      $func

}
