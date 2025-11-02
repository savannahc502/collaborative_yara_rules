rule is_CMD_Term {
	meta:
		description = "Detects the use of the cmd alias and the /c option"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
		$file = "cmd /c" // "/c" option has cmd run the command following it and exits
	condition:
		$file



}
