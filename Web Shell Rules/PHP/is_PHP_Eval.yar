rule is_PHP_Eval {
	meta:
		description = "Detects the use of the PHP eval function"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "10/31/2025"
	strings:
	    $func = "eval("
	condition:
      $func

}
