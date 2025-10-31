rule PLIST_FileTypeCheck
{
    meta:
        description = "Detects Mac OS DMG disk image files"
        author = "Connor East"
	date = "10/31/25"
        
    strings:
        $xml_plist = "<?xml" nocase
        $plist_tag = "<plist" nocase
        $binary_plist = "bplist"
        
    condition:
        ($xml_plist at 0 and $plist_tag) or $binary_plist at 0
}