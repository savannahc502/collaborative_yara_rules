rule is_PHP_Preg_Replace {
	meta:
		description = "Detects the use of the PHP preg_replace function"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
	    $func = /preg_replace\((\w+)\/e/ //checks for /e condition
	condition:
      $func

}
