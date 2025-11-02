rule lolbin_certutil
{
    meta:
        description = "Detects hex encoded certutil content"
        author = "Connor East"
        date = "02/11/25"
    strings:
        $certutil_hex = { 63 65 72 74 75 74 69 6C }
        $certutil_spaced = "63 65 72 74 75 74 69 6C"
    condition:
        any of them
}