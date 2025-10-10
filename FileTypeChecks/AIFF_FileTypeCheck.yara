// Needs to be tested
rule is_AIFF_File {
meta:
		description = "Detects AIFF file using headers and other hex identifiers"
    author = "Eamon Stackpole"
		editors = "Lily Pouliot"
		date = "2025-10-6"
		
	strings:
		$header = {46 4F 52 4D 00}
		$variant1 = "AIFF"
		$variant2 = "AIFC"
		$metadata = "COMM"
		$version = "FVER"
	
  condition:
	$header at 0 and 
    ($variant1 at 8 or $variant2 at 8 and
	$metadata

}
