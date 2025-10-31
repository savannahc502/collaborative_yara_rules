rule EPS_FileTypeCheck
{
    meta:
        description = "Detects Encapsulated PostScript files"
        author = "Connor East"
	date = "10/31/25"
        
    strings:
        $ps = { 25 21 50 53 2D 41 64 6F 62 65 }
        $eps = { 45 50 53 46 }
        
    condition:
        $ps at 0 and $eps