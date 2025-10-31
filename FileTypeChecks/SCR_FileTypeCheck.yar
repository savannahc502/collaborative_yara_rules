rule SCR_FileTypeCheck
{
    meta:
        description = "Detects Windows screensavers files"
        author = "Connor East"
	date = "10/31/25"

    strings:
        $mz = "MZ"
        $pe = "PE"
        
    condition:
        $mz at 0 and $pe
}