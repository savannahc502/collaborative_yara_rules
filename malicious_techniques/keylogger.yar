import "pe"
rule KeyloggerDetection {
    meta:
        description = "This script goes through and looks for keyloggers on your system. It checks for hooks or sync states and compares them with either the word keylog or log.txt"
        author = "Connor"
        date = "2025-01-17"
    
    strings:
        $k1 = "SetWindowsHookEx" $k2 = "GetAsyncKeyState" $k3 = "WH_KEYBOARD"
        $l1 = "keylog" nocase $l2 = "log.txt"
    condition:
        pe.is_pe and 2 of ($k*) and any of ($l*)
}
