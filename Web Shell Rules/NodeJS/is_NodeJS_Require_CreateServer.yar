rule is_NodeJS_Require_CreateServer {
	meta:
		description = "Detects the use of NodeJS require('http').createServer( function, which is used for reverse shells"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
		$func = "require('http').createServer("
	condition:
		$func


}