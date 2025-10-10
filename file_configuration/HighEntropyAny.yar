import "pe"
import "math"

rule HighEntropySection
{
    meta:
        description = "Detects sections with high entropy that contain .rsrc and .reloc"
        author = "Threat Hunter + Eamon Stackpole + Savannah Ciak + Connor East"
        editor = "Cameron Jalbert"
        date = "2025-10-09"

    strings:
        // String patterns found in packed executables
        // Append more packers to this list
        $packer1 = "UPX0" nocase
        $packer2 = "ASPack" nocase
        $packer3 = "SR" nocase

    condition:
        (
            for any i in (0..pe.number_of_sections - 1) :
                (
                    math.entropy(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) > 7.0
                    // and not pe.sections[i].name contains ".rsrc"
                    // and not pe.sections[i].name contains ".reloc"
                )
        )
        or any of ($packer*)
}
