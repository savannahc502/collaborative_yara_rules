rule is_NodeJS_Require_ReadFileSync {
	meta:
		description = "Detects the use of NodeJS require('fs').readFileSync( function"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
		$func = "require('fs').readFileSync("
	condition:
		$func


}