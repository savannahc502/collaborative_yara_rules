rule lolbin_msbuild
{
    meta:
        description = "Detects hex encoded msbuild content"
        author = "Connor East"
        date = "02/11/25"
    strings:
        $msbuild_hex = { 6D 73 62 75 69 6C 64 }
        $msbuild_spaced = "6D 73 62 75 69 6C 64"
    condition:
        any of them
}