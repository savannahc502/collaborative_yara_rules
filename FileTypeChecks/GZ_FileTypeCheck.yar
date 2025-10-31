rule GZ_FileTypeCheck
{
    meta:
        description = "Detects G-Zip files"
        author = "Connor East"
	date = "10/31/25"
        
    strings:
        $gzip = { 1F 8B }
        
    condition:
        $gzip at 0
}
