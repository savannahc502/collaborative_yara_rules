rule is_PHP_Assert {
	meta:
		description = "Detects the use of the PHP assert function"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
	    $func = "assert("
	condition:
      $func

}
