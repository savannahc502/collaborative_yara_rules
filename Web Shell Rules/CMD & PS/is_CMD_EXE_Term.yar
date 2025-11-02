rule is_CMD_EXE_Term {
	meta:
		description = "Detects the use of cmd.exe file and the /c option"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
		$file = "cmd.exe /c" // "/c" option has cmd run the command following it and exits
	condition:
		$file


}