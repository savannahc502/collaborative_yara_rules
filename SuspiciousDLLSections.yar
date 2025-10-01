import "pe"

rule SuspiciousDLLSectionCount {
    meta:
        description = "Checking dll specific files for less than 6 or more than 8 sections"
        author = "Lily Pouliot"
        date = "9/18/2025"
    strings:
        $dll_id1 = ".dll" nocase
        $dll_id2 = "LIBRARY" // common text in dll metadata
        $dll_id3 = "DllMain" // mandatory entry point in windows dll
        $dll_id4 = "kernel32" // almost every windows dll imports this function
        $dll_id5 = "DllEntryPoint" // alternate name for dll function
    condition:
      uint16(0) == 0x5A4D and // MZ header check
      uint32(uint32(0x3C)) ==  0x00004550 and // Pe header checker
      any of ($dll_id*) and //looks at the strings above 
      pe.number_of_sections < 6 or pe.number_of_sections > 8 // Section count checker
}
