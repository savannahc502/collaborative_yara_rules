rule lolbin_msexec
{
    meta:
        description = "Detects hex encoded msiexec content"
        author = "Connor East"
        date = "02/11/25"
    strings:
        $msiexec_hex = { 6D 73 69 65 78 65 63 }
        $msiexec_spaced = "6D 73 69 65 78 65 63"
    condition:
        any of them
}