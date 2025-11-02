rule is_Perl_Backticks {
	meta:
		description = "Detects the use of the Perl backticks function"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
	//  $tag = "#!/usr/bin/perl"
		$func = "backticks("
	condition:
    //  $tag and 
		$func

}