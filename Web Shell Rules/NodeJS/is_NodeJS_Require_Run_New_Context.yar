rule is_NodeJS_Require_Run_New_Context {
	meta:
		description = "Detects the use of NodeJS require('vm').runInNewContext( function"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
		$func = "require('vm').runInNewContext("
	condition:
		$func


}