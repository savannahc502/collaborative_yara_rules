import "pe"

rule SuspiciousSectionCount {
    meta:
        description = "Session Count Executable ++"
        author = "Threat Hunter + Connor East + Savannah"
        date = "2025-01-17"
    
    condition:
        (
            pe.number_of_sections > 10 or 
            pe.number_of_sections < 3
        ) and
        (
            uint16(0) != 0x5A4D or
            uint32(uint32(0x3c)) != 0x00004550 or
            (pe.characteristics & pe.DLL)
        )
}


