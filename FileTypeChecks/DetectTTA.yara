rule DetectTTA {
	meta:
		description = "Detects .tta files"
		author = "Connor"
		date = "2025-10-06"

	strings:
		$tta_header = { 54 54 51 }
		$tta_extension = ".tta"
	condition:
		$tta_header and $tta_extension
}
