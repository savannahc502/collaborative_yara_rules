rule lolbin_wmic
{
    meta:
        description = "Detects hex encoded wmic content"
        author = "Connor East"
        date = "02/11/25"
    strings:
        $wmic_hex = { 57 4D 49 43 }
        $wmic_spaced = "57 4D 49 43"
    condition:
        any of them
}