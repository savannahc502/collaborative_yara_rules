rule is_NodeJS_Require_Run_This_Context {
	meta:
		description = "Detects the use of the NodeJS require('vm').runInThisContext( function"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
		$func = "require('vm').runInThisContext("
	condition:
		$func



}
