rule is_PHP_Passthru {
	meta:
		description = "Detects the use of the PHP passthru function"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
	    $func = "passthru("
	condition:
      $func

}
