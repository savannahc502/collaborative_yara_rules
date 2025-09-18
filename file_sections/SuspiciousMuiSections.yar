import "pe"

rule SuspiciousEXESectionCount {
    meta:
        description = "Checking mui specific files for less than 6 or more than 8 sections"
        author = "Lily Pouliot"
        date = "9/18/2025"
    strings:
        $mui_int1 = "MUILangName"
        $mui_int2 = "MUIDisplayName"
        $mui_int3 = ".mui" nocase
    condition:
      uint16(0) == 0x5A4D and // MZ header check
      uint32(uint32(0x3C)) ==  0x00004550 and // Pe header checker
      any of ($mui_sig*) and //looks at the strings above for mui
      pe.number_of_sections > 2 // Section count checker
}
