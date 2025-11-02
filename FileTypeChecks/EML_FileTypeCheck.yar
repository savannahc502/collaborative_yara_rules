rule EML_FileTypeCheck
{
    meta:
        description = "Detects Outlook email EML files"
        author = "Connor East"
        date = "10/31/25"
        
    strings:
        $from = { 46 72 6F 6D 3A }
        $subject = { 53 75 62 6A 65 63 74 3A }
        $date = { 44 61 74 65 3A }
        
    condition:
        2 of them in (0..500)
}