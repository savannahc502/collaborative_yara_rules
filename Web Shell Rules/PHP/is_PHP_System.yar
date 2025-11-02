rule is_PHP_System {
	meta:
		description = "Detects the use of the PHP system function"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
	    $func = "system("
	condition:
      $func

}
