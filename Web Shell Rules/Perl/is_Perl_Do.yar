rule is_Perl_Do {
	meta:
		description = "Detects the use of the Perl do function"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
	    //$tag = "#!/usr/bin/perl"
		$func = "do("
	condition:
        //$tag and 
		$func

}