// Needs to be tested
rule is_PSD_File {
	meta:
		description = "Detects PSD file using file headers"
author = "Eamon Stackpole"
		editors = "N/A"
		date = "2025-10-6"
		
	strings:
		$header1 = { 38 42 50 53 }
	condition:
		$header*


}
