rule is_ASP_Create_WScript_Shell {
	meta:
		description = "Detects the use of the ASP Server.CreateObject function to make a Wscript Shell"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
		$func = "Server.CreateObject(\"WScript.Shell\")"
	condition:
		$func


}