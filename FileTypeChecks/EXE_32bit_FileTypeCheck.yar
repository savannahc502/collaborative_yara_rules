rule EXE_32bit_FileTypeCheck
{
    meta:
        description = "Detects 32bit exe files"
        author = "Connor East"
	date = "10/31/25"

    strings:
        $mz = "MZ"
        
    condition:
        $mz at 0 and
        uint32(uint32(0x3C)) == 0x00004550 and
        uint16(uint32(0x3C) + 0x18) == 0x010B
}