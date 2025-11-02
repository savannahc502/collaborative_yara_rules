rule CUR_FileTypeCheck
{
    meta:
        description = "Detects window cursor files"
        author = "Connor East"
	date = "10/31/25"

    strings:
        $magic = { 00 00 02 00 }
        
    condition:
        $magic at 0
}