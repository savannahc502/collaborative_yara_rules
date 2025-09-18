import "pe"

rule SuspiciousSYSSectionCount {
    meta:
        description = "Checking sys specific files for less than 9 or more than 13 sections"
        author = "Lily Pouliot"
        date = "9/18/2025"
    strings:
        $sys_int1 = ".sys" nocase
        $sys_int2 = "ntoskrnl"
        $sys_int3 = "DRIVER"
        $sys_int3 = "DriverEntry"
    condition:
      uint16(0) == 0x5A4D and // MZ header check
      uint32(uint32(0x3C)) ==  0x00004550 and // Pe header checker
      any of ($sys_sig*) and //looks at the strings above 
      pe.number_of_sections < 9 or pe.number_of_sections > 13 // Section count checker
}
