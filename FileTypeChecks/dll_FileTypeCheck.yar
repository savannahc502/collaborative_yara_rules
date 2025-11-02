rule dll_FileTypeCheck
{
    meta:
        description = "Detects dlls"
        author = "Connor East"
        date = "2025-11-01"
        
    strings:
        $mz_header = { 4D 5A }
        $pe_signature = { 50 45 00 00 }

    condition:
        $mz_header at 0 and 
        $pe_signature in (0..1024) and
        uint16(uint32(0x3C) + 0x16) & 0x2000
}