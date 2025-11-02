rule is_JSP_Class_GetMethod_Invoke {
	meta:
		description = "Detects the use of JSP Class.forName(.getMethod(.invoke( function "
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
		$func = "Class.forName(.getMethod().invoke("
	condition:
		$func



}
