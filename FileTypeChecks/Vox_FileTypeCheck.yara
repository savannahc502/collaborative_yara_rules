rule DetectVox {
	meta:
		description = "Detects .vox files using file headers"
		author = "Connor"
		editor = "Lily Pouliot"
		date = "2025-10-06"

	strings:
		$vox_mark = {00 00 00 00} /placeholder since Vox ha no standard header 

	condition:
		filesize < 10MB and
		filesize > 100 

}
