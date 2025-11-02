rule is_PHP_Move_Uploaded_File {
	meta:
		description = "Detects the use of the PHP move_uploaded_file function"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
	    $func = "move_uploaded_file("
	condition:
      $func

}
