rule SevenZ_FileTypeCheck
{
    meta:
        description = "Detects 7-ZIP archive files"
        author = "Connor East"
	date = "10/31/25"

    strings:
        $7z = { 37 7A BC AF 27 1C }
        
    condition:
        $7z at 0
}