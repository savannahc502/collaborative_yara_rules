rule lolbin_rundll32_hex
{
    meta:
        description = "Detects hex encoded rundll32 content"
        author = "Connor East"
        date = "02/11/25"
    strings:
        $rundll_hex = { 52 75 6E 64 6C 6C 33 32 }
        $rundll_spaced = "52 75 6E 64 6C 6C 33 32"
    condition:
        any of them

}
