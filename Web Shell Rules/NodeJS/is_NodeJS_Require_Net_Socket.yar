rule is_NodeJS_Require_Net_Socket {
	meta:
		description = "Detects the use of NodeJS require('net').Socket( function which is used for outbound connections"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
		$func = "require('net').Socket("
	condition:
		$func


}