rule DOC_FileTypeCheck
{
    meta:
        description = "Detects .DOC files"
        author = "Connor East"
	date = "10/31/25"
        
    strings:
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }
        $word_doc = "WordDocument" wide ascii
        $msword = { EC A5 C1 00 } // Word document signature
        
    condition:
        $ole at 0 and ($word_doc or $msword)
}