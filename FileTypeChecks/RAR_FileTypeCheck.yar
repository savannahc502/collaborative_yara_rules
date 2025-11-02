rule RAR_FileTypeCheck
{
    meta:
        description = "Detects Mac OS DMG disk image files"
        author = "Connor East"
	date = "10/31/25"
        
    strings:
        $rar4 = { 52 61 72 21 1A 07 00 }
        $rar5 = { 52 61 72 21 1A 07 01 00 }
        
    condition:
        $rar4 at 0 or $rar5 at 0
}
