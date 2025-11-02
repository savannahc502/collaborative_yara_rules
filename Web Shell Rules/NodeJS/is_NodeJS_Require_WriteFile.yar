rule is_NodeJS_Require_WriteFile {
	meta:
		description = "Detects the use of NodeJS require('fs').writeFile( function"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
		$func = "require('fs').writeFile("
	condition:
		$func


}