rule is_Perl_Require {
	meta:
		description = "Detects the use of the Perl require function"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
	    $tag = "#!/usr/bin/perl"
		$func = "require("
	condition:
        $tag and 
		$func

}