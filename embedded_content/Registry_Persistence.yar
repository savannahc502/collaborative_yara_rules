import "pe"

rule Registry_Persistence_Advanced {
    meta:
        description = "Detects advanced registry persistence mechanisms"
        author = "Cameron"
        date = "2025-09-21"
    strings:
        // Registry API functions
        $reg1 = "RegCreateKeyExA" ascii
        $reg2 = "RegCreateKeyExW" ascii
        $reg3 = "RegSetValueExA" ascii
        $reg4 = "RegSetValueExW" ascii
        // Common persistence registry keys
        $run_key = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $runonce = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii wide nocase
        $winlogon = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii wide nocase
        $services = "System\\CurrentControlSet\\Services" ascii wide nocase
        // Image File Execution Options (debugger hijacking)
        $ifeo = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options" ascii wide nocase
        // AppInit_DLLs
        $appinit = "AppInit_DLLs" ascii wide
        // SilentProcessExit monitoring
        $silent = "SilentProcessExit" ascii wide
    condition:
        pe.is_pe and
        2 of ($reg*) and
        (2 of ($run_key, $runonce, $winlogon, $services) or
         1 of ($ifeo, $appinit, $silent))
}
