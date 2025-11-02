rule is_PHP_Proc_Open {
	meta:
		description = "Detects the use of the PHP proc_open function"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
	    $func = "proc_open("
	condition:
      $func

}
