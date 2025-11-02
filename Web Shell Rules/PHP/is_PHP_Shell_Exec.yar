rule is_PHP_Shell_Exec {
	meta:
		description = "Detects the use of the PHP shell_exec function"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
	    $func = "shell_exec("
	condition:
      $func

}
