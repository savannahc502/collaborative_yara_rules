rule is_ASP_Response_Write {
	meta:
		description = "Detects the use of the ASP Response.Write function"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
		$func = "Response.Write("
	condition:
		$func


}