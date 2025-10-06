rule HEIF_Imagechecker {
	meta:
		author = "Louis Mattiolo"
		date = "Oct 6th 2025"
		description = "Detect HEIF image files based on headers"

strings: 
	$ftyp = "ftyp" ascii //ftyp is filetype for heif&heic files
	$heic = "heic" ascii
	$heix = "heix" ascii
	$mif1 = "mif1" ascii 
	$msf1 = "msf1" ascii
	$hevc = "hevc" ascii
	$avci = "avci" ascii

condition:
	$ftyp at 4 and any of ($heic, $heix, $mif1, $msf1, $hevc, $avci) at 0
}
