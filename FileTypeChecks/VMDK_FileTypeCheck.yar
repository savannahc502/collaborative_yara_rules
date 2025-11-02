rule VMDK_FileTypeCheck
{
    meta:
        description = "Detects VMDK files"
        author = "Connor East"
	date = "10/31/25"

    strings:
        $kdm = { 4B 44 4D }
        $cowd = { 43 4F 57 44 }
        $vmdk_text = "# Disk DescriptorFile"
        
    condition:
        $kdm at 0 or $cowd at 0 or $vmdk_text at 0
}