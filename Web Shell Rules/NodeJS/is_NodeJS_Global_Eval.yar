rule is_NodeJS_Global_Eval {
	meta:
		description = "Detects the use of NodeJS global.eval( function"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
		$func = "global.eval("
	condition:
		$func


}