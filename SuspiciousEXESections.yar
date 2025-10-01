import "pe"

rule SuspiciousEXESectionCount {
    meta:
        description = "Checking exe for less than 6 or more than 8 sections"
        author = "Lily Pouliot"
        date = "9/17/2025"
    condition:
      uint16(0) == 0x5A4D and // MZ header check
      uint32(uint32(0x3C)) ==  0x00004550 and // Pe header checker
      (pe.number_of_sections < 6 or pe.number_of_sections > 8)
}
