rule is_PHP_fwrite {
	meta:
		description = "Detects the use of the PHP fwrite function"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
	    $func = "fwrite("
	condition:
      $func

}
