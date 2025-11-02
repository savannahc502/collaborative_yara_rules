rule is_PHP_Copy {
	meta:
		description = "Detects the use of the PHP copy function"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
	    $func = "copy("
	condition:
      $func

}
