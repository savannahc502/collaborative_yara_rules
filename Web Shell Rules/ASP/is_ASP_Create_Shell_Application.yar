rule is_ASP_Create_Shell_Application {
	meta:
		description = "Detects the use of the ASP Server.CreateObject function to make a shell application"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
		$func = "Server.CreateObject(\"Shell.Application\")"
	condition:
		$func


}