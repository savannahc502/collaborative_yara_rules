import "pe"
import "math"

rule HighEntropySection {
	meta:
		description = "Detects sections with high entropy"
		author = "Threat Hunter + Eamon Stackpole"
		editor = "Savannah Ciak && Connor East" 
		date = "2025-9-17"
	strings:
		// String patterns found in packed executables
		// Append more packers to this lists
		$packer1 = "UPX0" nocase
		$packer2 = "ASPack" nocase
		$packer3 = "SR"
    condition:
        (
            for any i in (0..pe.number_of_sections-1) : (
                math.entropy(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) > 7.0 and
                not pe.sections[i].name contains ".rsrc" and
                not pe.sections[i].name contains ".reloc"
            )
        ) or
        any of ($packer*)
}
