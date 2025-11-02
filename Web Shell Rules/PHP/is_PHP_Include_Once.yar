rule is_PHP_Include_Once {
	meta:
		description = "Detects the use of the PHP include_once function"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
	    $func = "include_once("
	condition:
      $func

}
