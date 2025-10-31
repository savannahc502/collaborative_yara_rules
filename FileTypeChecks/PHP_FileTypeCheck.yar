rule PHP_FileTypeCheck
{
    meta:
        description = "Detects html files"
        author = "Connor East"
	date = "10/31/25"
        
    strings:
        $php1 = "<?php"
        $php2 = "<?="
        
    condition:
        $php1 in (0..100) or $php2 in (0..100)
}