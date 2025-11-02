rule MDB_FileTypeCheck
{
    meta:
        description = "Detects .MDB files"
        author = "Connor East"
	date = "10/31/25"
        
    strings:
        $jet3 = { 00 01 00 00 53 74 61 6E 64 61 72 64 20 4A 65 74 20 44 42 }
        $jet4 = { 00 01 00 00 53 74 61 6E 64 61 72 64 20 41 43 45 20 44 42 }
        
    condition:
        $jet3 at 0 or $jet4 at 0
}
