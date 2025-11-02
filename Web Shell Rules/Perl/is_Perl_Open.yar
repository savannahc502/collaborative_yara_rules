rule is_Perl_Open {
	meta:
		description = "Detects the use of the Perl open function"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
	    //$tag = "#!/usr/bin/perl"
		$func = /open\((\w+), \"(\w+)\|\"/ // with pipe (e.g., open(File, "command |"))
	condition:
      //$tag and 
	  $func


}
