rule JAR_FileTypeCheck
{
    meta:
        description = "Detects Java jar files"
        author = "Connor East"
	date = "10/31/25"
        
    strings:
        $zip = { 50 4B 03 04 }
        $manifest = "META-INF/MANIFEST.MF"
        
    condition:
        $zip at 0 and $manifest
}