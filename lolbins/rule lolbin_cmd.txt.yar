rule lolbin_cmd
{
    meta:
        description = "Detects hex encoded cmd content"
        author = "Connor East"
        date = "02/11/25"
    strings:
        $cmd_hex = { 63 6D 64 2E 65 78 65 }
        $cmd_spaced = "63 6D 64 2E 65 78 65"
    condition:
        any of them
}