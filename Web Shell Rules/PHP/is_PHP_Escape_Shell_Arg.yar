rule is_PHP_Escape_Shell_Arg {
	meta:
		description = "Detects the use of the PHP escapeshellarg function"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
	    $func = "escapeshellarg("
	condition:
      $func

}
