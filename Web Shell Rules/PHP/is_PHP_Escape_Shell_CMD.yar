rule is_PHP_Escape_Shell_CMD {
	meta:
		description = "Detects the use of the PHP escapeshellcmd function"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
	    $func = "escapeshellcmd("
	condition:
      $func

}
