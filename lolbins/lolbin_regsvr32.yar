rule lolbin_regsvr32
{
    meta:
        description = "Detects hex encoded regsvr32 content"
        author = "Connor East"
        date = "02/11/25"
    strings:
        $regsvr_hex = { 72 65 67 73 76 72 33 32 }
        $regsvr_spaced = "72 65 67 73 76 72 33 32"
    condition:
        any of them
}