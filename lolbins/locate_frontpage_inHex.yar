rule locate_frontpage_inHex
{
    meta:
        description = "Locates the section in which frontpage is located in the original malware."
        author = "Connor East"
        date = "02/11/25"  
    strings:
        $frontpage_hex = { 66 72 6F 6E 74 70 61 67 65 2E 6A 70 67 }
        $frontpage_spaced = "66 72 6F 6E 74 70 61 67 65 2E 6A 70 67"
    condition:
        any of them

}
