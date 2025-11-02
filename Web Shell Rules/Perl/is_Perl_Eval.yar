rule is_Perl_Eval {
	meta:
		description = "Detects the use of the Perl eval function"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
	    $tag = "#!/usr/bin/perl"
		$func = "eval("
	condition:
        $tag and 
		$func

}