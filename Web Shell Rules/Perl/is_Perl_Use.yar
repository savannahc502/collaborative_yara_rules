rule is_Perl_Use {
	meta:
		description = "Detects the use of the Perl use function"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
	//  $tag = "#!/usr/bin/perl"
		$func = "use("
	condition:
    //  $tag and 
		$func

}