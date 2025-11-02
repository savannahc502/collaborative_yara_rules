rule is_PHP_Require_Once {
	meta:
		description = "Detects the use of the PHP require_once function"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
	    $func = "require_once("
	condition:
      $func

}
