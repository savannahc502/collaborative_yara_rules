rule embedded_PE{
	meta:
		description = "Detects multiple Portable Executables (PE) embedded  in the file"
		author = "Eamon Stackpole"
		editor = "Savannah Ciak"
		date = "2025-9-17"
	strings:
		$line = /This program cannot be run in DOS mode/
	condition:
		#line >= 2

}

