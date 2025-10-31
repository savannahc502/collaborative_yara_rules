rule PPTX_FileTypeCheck
{
    meta:
        description = "Detects PowerPoint PPTX files"
        author = "Connor East"
	date = "10/31/25"
        
    strings:
        $zip = { 50 4B 03 04 }
        $content_types = "[Content_Types].xml"
        $ppt_marker = "ppt/"
        
    condition:
        $zip at 0 and $content_types and $ppt_marker
}