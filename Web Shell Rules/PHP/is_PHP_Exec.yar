rule is_PHP_Exec {
	meta:
		description = "Detects the use of the PHP exec function"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
	    $func = "exec("
	condition:
      $func

}
