rule RTF_FileTypeCheck
{
    meta:
        description = "Detects RTF files"
        author = "Connor East"
	date = "10/31/25"

    strings:
        $rtf = { 7B 5C 72 74 66 31 }
        
    condition:
        $rtf at 0
}