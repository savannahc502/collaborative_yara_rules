// Needs to be tested
rule is_AAC_File {
meta:
		description = "Detects AAC file using file headers"
    author = "Eamon Stackpole"
		editors = "Lily Pouliot"
		date = "2025-10-6"
		
	strings:
		$header1 = { FF F1 }
		$header2 = { FF F9 }
	
  condition:
		($header1 at 0) or ($header2 at 0)

}
