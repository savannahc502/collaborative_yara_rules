rule is_NodeJS_Require_CreateWriteStream {
	meta:
		description = "Detects the use of the NodeJS require('fs').createWriteStream( function"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
		$func = "require('fs').createWriteStream("
	condition:
		$func



}
