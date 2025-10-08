rule DetectWMA {
	meta:
		description = "Detects .wma files using headers and other hex identifiers"
		author = "Connor"
		date = "2025-10-06"

	strings:
		$wma_header = { 30 26 B2 75 8E 66 CF 11 A6 D9 00 AA 00 62 CE 6C }
		$wma_extension = ".wma"
	
  condition:
		$wma_header and $wma_extension
}
