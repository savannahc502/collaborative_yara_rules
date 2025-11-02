rule locate_fileview_inHex
{
    meta:
        description = "Locates the section in which fileview is located in the original malware."
        author = "Connor East"
        date = "02/11/25"  
    strings:
        $fileview_hex = { 66 69 6C 65 76 69 65 77 2E 65 78 65 }
        $fileview_spaced = "66 69 6C 65 76 69 65 77 2E 65 78 65"
    condition:
        any of them
}