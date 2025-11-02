rule EXE_64bit_FileTypeCheck
{
    meta:
        description = "Detects 64bit exe files"
        author = "Connor East"
	date = "10/31/25"

    strings:
        $mz = "MZ"
        
    condition:
        $mz at 0 and
        uint32(uint32(0x3C)) == 0x00004550 and
        uint16(uint32(0x3C) + 0x18) == 0x020B
}