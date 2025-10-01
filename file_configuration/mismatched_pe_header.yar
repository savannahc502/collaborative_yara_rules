// import "pe" // imports the PE module, not needed for this function

rule pe_magic_number {
  meta:
    description = "Detects files that contain a valid PE header at the correct offset, BUT do not start with the standard magic number MZ" 
	author = "Savannah Ciak"
	date = "2025-9-17"
  condition:
	uint32(0x3C) < filesize and 
		// Reads 4 bytes at offset 0x3C, which is where the DOS header stores the pointer to the PE header.
	uint32(uint32(0x3C)) == 0x00004550 and 
		// gets the offset to the PE header, reads 4 bytes at that offset. 
		// 0x00004550 is the hex representation of the ASCII string PE\0\0, which is the signature of a PE file.
	uint16(0) != 0x5A4D
		// 0x5A4D is the hex value for MZ, the magic number that identifies a valid DOS header.
}
