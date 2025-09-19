import "pe"
rule HighEntropySection {
	meta:
		description = "Detects sections with high entropy"
		author = "Threat Hunter + Eamon Stackpole"
		editor = "Savannah Ciak" 
		date = "2025-9-17"
	strings:
		// String patterns found in packed executables
		// Append more packers to this lists
		$packer1 = "UPX0" nocase
		$packer2 = "ASPack" nocase
		$packer3 = "SR"
    condition:
        (
            for any section in pe.sections : (
                section.entropy > 7.0 and 
                not section.name contains ".rsrc" and
                not section.name contains ".reloc"
            )
        ) or
        any of ($packer*)
}
