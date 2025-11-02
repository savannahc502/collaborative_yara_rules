rule is_PHP_File_Get_Contents {
	meta:
		description = "Detects the use of the PHP file_get_contents function"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
	    $func = "file_get_contents("
	condition:
      $func

}
