// import "pe" // imports the PE module, not needed for this function

rule pe_magic_number {
  meta:
    description = "Detects PE files with a tampered DOS header (missing MZ aka 0x5A4D)" 
	author = "Savannah Ciak"
	date = "2025-9-17"
  condition:
	uint32(0x3C) < filesize and
	uint32(uint32(0x3C)) == 0x00004550 and
	uint16(0) != 0x5A4D
}
