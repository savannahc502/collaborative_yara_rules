rule DetectVox {
	meta:
		description = "Detects .vox files using file headers"
		author = "Connor"
		date = "2025-10-06"
	strings:
		$header = {56 6F 78 20}
	condition:
		$header at 0

}
