rule VHD_FileTypeCheck
{
    meta:
        description = "Detects VHD files"
        author = "Connor East"
	date = "10/31/25"

    strings:
        $conectix = { 63 6F 6E 65 63 74 69 78 }
        
    condition:
        $conectix at filesize - 512
}