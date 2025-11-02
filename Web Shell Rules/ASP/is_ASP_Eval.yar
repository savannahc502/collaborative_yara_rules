rule is_ASP_Eval {
	meta:
		description = "Detects the use of the ASP eval function"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
		$tag = /\<\%(\w+)\%\>/ //checks for the ASP tag "<%.......%>" in file
		$func = "Eval("
	condition:
		$tag and $func


}