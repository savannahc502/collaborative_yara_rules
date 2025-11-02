rule lolbin_wmic
{
    meta:
        description = "Detects hex encoded wmic content"
        author = "Connor East"
        date = "02/11/25"  
    strings:
        $cmd1 = { 63 6D 64 2E 65 78 65 }
        $cmd2 = "63 6D 64 2E 65 78 65"
        $createdir1 = { 43 72 65 61 74 65 44 69 72 65 63 74 6F 72 79 }
        $createdir2 = "43 72 65 61 74 65 44 69 72 65 63 74 6F 72 79"
    condition:
        (any of (cmd*)) and (any of (createdir*))
}