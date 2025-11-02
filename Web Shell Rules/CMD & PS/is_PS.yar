rule is_PS {
	meta:
		description = "Detects the use of powershell alias"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
		$file = "powershell"
	condition:
		$file


}