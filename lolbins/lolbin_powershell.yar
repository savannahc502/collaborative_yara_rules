rule lolbin_powershell
{
    meta:
        description = "Detects hex encoded powershell content"
        author = "Connor East"
        date = "02/11/25"
    strings:
        $ps_hex = { 70 6F 77 65 72 73 68 65 6C 6C }
        $ps_spaced = "70 6F 77 65 72 73 68 65 6C 6C"
    condition:
        any of them
}