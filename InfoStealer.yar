import "pe"
rule InfoStealer {
    meta:
        description = "Script to locate files which are attempting to gain access to either saved web info or cookies"
        author = "Connor"
        date = "2025-01-17"
    
    strings:
        $b1 = "Chrome" $b2 = "Firefox" $b3 = "passwords"
        $f1 = "Login Data" $f2 = "cookies" $f3 = "wallet"
    condition:
        pe.is_pe and 2 of ($b*) and any of ($f*)
}