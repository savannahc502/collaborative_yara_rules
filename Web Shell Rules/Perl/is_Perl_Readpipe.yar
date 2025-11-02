rule is_Perl_Readpipe {
	meta:
		description = "Detects the use of the Perl readpipe function"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
	//  $tag = "#!/usr/bin/perl"
		$func = "readpipe("
	condition:
    //  $tag and 
		$func

}