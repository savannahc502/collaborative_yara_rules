rule DetectVox {
	meta:
		description = "Detects .vox files"
		author = "Connor"
		date = "2025-10-06"
	condition:
		extension == ".vox"

}
