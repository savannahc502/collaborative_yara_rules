// Needs to be tested
rule is_ALAC_File {
	meta:
		description = "Detects ALAC file using the file header"
author = "Eamon Stackpole"
		editors = "N/A"
		date = "2025-10-6"
		
	strings:
		$mp4_header = { 66 74 79 70 }
		$alac_header = { 61 6C 61 63 }
	condition:
		$mp4_header and $alac_header

}
