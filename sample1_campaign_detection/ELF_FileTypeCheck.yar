rule ELF_FileTypeCheck
{
    meta:
        description = "Detects linux elf files"
        author = "Connor East"
	date = "10/31/25"

    strings:
        $elf = { 7F 45 4C 46 }
        
    condition:
        $elf at 0
}
