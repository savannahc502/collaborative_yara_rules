rule QEMU_FileTypeCheck
{
    meta:
        description = "Detects Mac OS DMG disk image files"
        author = "Connor East"
	date = "10/31/25"
        
    strings:
        $qfi = { 51 46 49 FB }
        
    condition:
        $qfi at 0
}