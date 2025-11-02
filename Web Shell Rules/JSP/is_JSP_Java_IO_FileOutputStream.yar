rule is_JSP_Java_IO_FileOutputStream {
	meta:
		description = "Detects the use of JSP new java.io.FileOutputStream( function "
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
		$func = "new java.io.FileOutputStream(("
	condition:
		$func


}