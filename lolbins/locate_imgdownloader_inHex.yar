rule locate_imgdownloader_inHex
{
    meta:
        description = "Locates the section in which ImageDownloader is located in the original malware."
        author = "Connor East"
        date = "02/11/25"  
    strings:
        $imgdl_hex = { 69 6D 61 67 65 5F 64 6F 77 6E 6C 6F 61 64 65 72 2E 65 78 65 }
        $imgdl_spaced = "69 6D 61 67 65 5F 64 6F 77 6E 6C 6F 61 64 65 72 2E 65 78 65"
    condition:
        any of them
}