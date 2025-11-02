rule is_ASP_Create_ADODB_Stream {
	meta:
		description = "Detects the use of the ASP Server.CreateObject function to make a ADODB stream"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
		$func = "Server.CreateObject(\"ADODB.Stream\")"
	condition:
		$func


}