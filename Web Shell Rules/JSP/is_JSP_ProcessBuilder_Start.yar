rule is_JSP_ProcessBuilder_Start {
	meta:
		description = "Detects the use of JSP ProcessBuilder.start( function"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
		$func = "ProcessBuilder.start("
	condition:
		$func


}