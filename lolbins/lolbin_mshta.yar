rule lolbin_mshta
{
    meta:
        description = "Detects hex encoded mshta content"
        author = "Connor East"
        date = "02/11/25"
    strings:
        $mshta_hex = { 6D 73 68 74 61 }
        $mshta_spaced = "6D 73 68 74 61"
    condition:
        any of them
}