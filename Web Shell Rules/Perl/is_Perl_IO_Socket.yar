rule is_Perl_IO_Socket {
	meta:
		description = "Detects the use of the Perl IO socket function"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
	    //$tag = "#!/usr/bin/perl"
		$func = "IO::Socket"
	condition:
        //$tag and 
		$func

}