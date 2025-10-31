rule SWF_FileTypeCheck
{
    meta:
        description = "Detects SWF files"
        author = "Connor East"
	date = "10/31/25"

    strings:
        $fws = { 46 57 53 }
        $cws = { 43 57 53 }
        $zws = { 5A 57 53 }
        
    condition:
        $fws at 0 or $cws at 0 or $zws at 0
}