rule is_JSP_System_Set {
	meta:
		description = "Detects the use of the JSP System.setIn(, System.setOut(, and System.setErr( functions which are used for stream manipulation"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
		$func1 = "System.setIn(" //Input Stream
		$func2 = "System.setOut(" //Output Stream
		$func3 = "System.setErr(" //Error Stream
	condition:
		any of ($func*)


}