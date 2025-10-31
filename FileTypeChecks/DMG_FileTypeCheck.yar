rule DMG_FileTypeCheck
{
    meta:
        description = "Detects DMG files"
        author = "Connor East"
	date = "10/31/25"
        
    strings:
        $magic = { 78 01 73 0D 62 62 60 }
        
    condition:
        $magic at 0
}