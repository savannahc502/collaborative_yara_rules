rule is_ASP_Server_Execute {
	meta:
		description = "Detects the use of the ASP Server.Execute function"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
		$func = "Server.Execute("
	condition:
		$func


}