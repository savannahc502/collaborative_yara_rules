rule is_PS_EXE {
	meta:
		description = "Detects the use of powershell.exe file"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
		$file = "powershell.exe"
	condition:
		$file


}