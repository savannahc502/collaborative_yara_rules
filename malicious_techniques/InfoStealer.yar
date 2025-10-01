import "pe"
rule InfoStealer {
    meta:
        description = "Script to locate files which are attempting to gain access to either saved web info or cookies"
        author = "Connor East"
        editor = "Savannah Ciak"
        date = "2025-01-17"
    
    strings:
        $b1 = "Chrome" ascii wide nocase
        $b2 = "Firefox" ascii wide nocase
        $b3 = "passwords" ascii wide nocase
        $f1 = "Login Data" ascii wide nocase
        $f2 = "cookies" ascii wide nocase
        $f3 = "wallet" ascii wide nocase
    condition:
        pe.is_pe and 2 of ($b*) and any of ($f*)

}
