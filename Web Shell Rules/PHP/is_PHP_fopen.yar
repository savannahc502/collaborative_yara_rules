rule is_PHP_fopen {
	meta:
		description = "Detects the use of the PHP fopen function"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
	    $func = "fopen("
	condition:
      $func

}
