rule is_NodeJS_Require_ExecSync {
	meta:
		description = "Detects the use of NodeJS require('child_process').execSync( function"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
		$func = "require('child_process').execSync("
	condition:
		$func


}