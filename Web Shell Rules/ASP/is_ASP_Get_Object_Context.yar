rule is_ASP_Get_Object_Context {
	meta:
		description = "Detects the use of the ASP GetObjectContext function"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
		$func = "GetObjectContext("
	condition:
		$func


}