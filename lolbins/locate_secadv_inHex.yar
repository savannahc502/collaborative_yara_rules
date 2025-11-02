rule locate_secadv_inHex
{
    meta:
        description = "Locates the section in which SecurityAdvisory is created in the exec."
        author = "Connor East"
        date = "02/11/25"  
    strings:
        $secadv_hex = { 53 65 63 75 72 29 74 79 41 64 76 69 73 6F 72 79 2E 64 6F 63 6D }
        $secadv_spaced = "53 65 63 75 72 29 74 79 41 64 76 69 73 6F 72 79 2E 64 6F 63 6D"
    condition:
        any of them
}