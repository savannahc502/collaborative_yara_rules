rule is_Perl_Fork {
	meta:
		description = "Detects the use of the Perl fork function"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
	    //$tag = "#!/usr/bin/perl"
		$func1 = "fork(" //combined with exec(
		$func2 = "exec("
	condition:
        //$tag and 
		$func1 and $func2


}
