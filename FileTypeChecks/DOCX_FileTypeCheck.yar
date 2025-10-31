rule DOCX_FileTypeCheck
{
    meta:
        description = "Detects DOCX files"
        author = "Connor East"
	date = "10/31/25"
        
    strings:
        $zip = { 50 4B 03 04 }
        $content_types = "[Content_Types].xml"
        $word_marker = "word/"
        
    condition:
        $zip at 0 and $content_types and $word_marker
}