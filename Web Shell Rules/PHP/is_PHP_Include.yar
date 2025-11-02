rule is_PHP_Include {
	meta:
		description = "Detects the use of the PHP include function"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
	    $func = "include("
	condition:
      $func

}
