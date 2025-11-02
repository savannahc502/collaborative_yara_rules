rule PIF_FileTypeCheck
{
    meta:
        description = "Detects Mac OS DMG disk image files"
        author = "Connor East"
	date = "10/31/25"
        
    strings:
        $mz = "MZ"
        
    condition:
        $mz at 0 and uint16(0x18) == 0x0040
}