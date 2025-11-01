rule UPX_FileTypeCheck
{
    meta:
        description = "Detects UPX packed executables"
        author = "Connor East"
        date = "2025-11-01"
        
    strings:
        $upx0 = { 55 50 58 30 }
        $upx1 = { 55 50 58 31 }
        $upx_sig = { 55 50 58 21 }
        
    condition:
        uint16(0) == 0x5A4D and any of them
}