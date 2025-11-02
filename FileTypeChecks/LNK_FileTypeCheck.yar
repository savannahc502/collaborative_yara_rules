rule LNK_FileTypeCheck
{
    meta:
        description = "Detects windows lnk files files"
        author = "Connor East"
	date = "10/31/25"

    strings:
        $magic = { 4C 00 00 00 01 14 02 00 }
        
    condition:
        $magic at 0
}