// Needs to be tested
rule is_ALAC_File {
	meta:
		description = "Detects ALAC file using the file header"
author = "Eamon Stackpole"
		editors = "Lily Pouliot"
		date = "2025-10-6"
		
	strings:
		$ftyp_header = { 66 74 79 70} 
		$mp4_header = { 66 74 79 70 }
		$alac_header = { 61 6C 61 63 }
	condition:
		$ftyp_header at 4 and
		$mp4_header in (8..16) and 
		$alac_header

}
