rule EVTX_FileTypeCheck
{
    meta:
        description = "Detects eventlog files"
        author = "Connor East"
	date = "10/31/25"
        
    strings:
        $magic = { 45 6C 66 46 69 6C 65 00 }
        
    condition:
        $magic at 0
}

