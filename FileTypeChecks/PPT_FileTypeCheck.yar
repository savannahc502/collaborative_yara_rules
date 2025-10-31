rule PPT_FileTypeCheck
{
    meta:
        description = "Detects PowerPoint PPTX files"
        author = "Connor East"
	date = "10/31/25"
        
    strings:
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }
        $powerpoint = "PowerPoint Document" wide ascii
        $current_user = "Current User" wide ascii
        
    condition:
        $ole at 0 and ($powerpoint or $current_user)
}