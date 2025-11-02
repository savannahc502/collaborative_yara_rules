rule HTML_FileTypeCheck
{
    meta:
        description = "Detects html files"
        author = "Connor East"
	date = "10/31/25"
        
    strings:
        $html1 = "<!DOCTYPE html" nocase
        $html2 = "<html" nocase
        $html3 = "<HTML" nocase
        
    condition:
        $html1 at 0 or $html2 in (0..100) or $html3 in (0..100)
}