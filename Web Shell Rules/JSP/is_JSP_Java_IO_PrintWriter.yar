rule is_JSP_Java_IO_PrintWriter {
	meta:
		description = "Detects the use of the JSP new java.io.PrintWriter( function "
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
		$func = "new java.io.PrintWriter("
	condition:
		$func



}
