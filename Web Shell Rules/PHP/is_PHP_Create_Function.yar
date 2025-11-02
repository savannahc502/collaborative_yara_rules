rule is_PHP_Create_Function {
	meta:
		description = "Detects the use of the PHP create_function function"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
	    $func = "create_function("
	condition:
      $func

}
