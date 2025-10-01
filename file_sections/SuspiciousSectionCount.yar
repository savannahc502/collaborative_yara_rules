import "pe"

rule SuspiciousSectionCount {
    meta:
        description = "Flags PE files with abnormal section counts (less than 3 or more than 10)"
        author = "Threat Hunter + Connor East + Savannah Ciak"
        date = "2025-01-17"
    
    condition:
        uint16(0) == 0x5A4D and
        uint32(uint32(0x3C)) == 0x00004550 and
        (
            pe.number_of_sections < 3 or 
            pe.number_of_sections > 10
        )
}
