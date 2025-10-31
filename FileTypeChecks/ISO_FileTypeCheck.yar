rule ISO_FileTypeCheck
{
    meta:
        description = "Detects iso files"
        author = "Connor East"
	date = "10/31/25"
        
    strings:
        $cd001 = { 43 44 30 30 31 }
        
    condition:
        $cd001 at 0x8001 or $cd001 at 0x8801 or $cd001 at 0x9001
}
