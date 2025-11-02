rule is_NodeJS_Require_Spawn {
	meta:
		description = "Detects the use of the NodeJS require('child_process').spawn( function"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
		$func = "require('child_process').spawn("
	condition:
		$func



}
