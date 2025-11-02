rule is_NodeJS_Eval {
	meta:
		description = "Detects the use of the NodeJS eval function"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
		$node = /require\(\'(\w+)\'\)/ //require is used to call NodeJS modules, indicator for NodeJS
		$func = "eval("
	condition:
		$node and $func



}
