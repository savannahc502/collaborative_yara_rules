rule ThugBehavioralChange {
    meta:
        description = "A script meant to locate all malicious files in the thug campaign"
        author = "Connor East"
        date = "2025-10-09"
    strings:
    // File Types
        $ft_pe = { 4D 5A }
        $ft_ole = { D0 CF 11 E0 A1 B1 1A E1 }
        $ft_jpg = { FF D8 FF }
        $ft_bmp = { 42 4D }
        $ft_png = { 89 50 4E 47 }
        $ft_zip = { 50 4B 03 04 }
    // Injection
        $inject1 = "CreateRemoteThread" ascii wide
        $inject2 = "WriteProcessMemory" ascii wide
        $inject3 = "VirtualAllocEx" ascii wide
    // Persistence
        $persist1 = "Startup" ascii wide
        $persist2 = "Run" ascii wide
    // Downloading capabilities
        $http1 = "XMLHTTP" ascii wide nocase
        $http2 = "WinHttp" ascii wide nocase
        $http3 = "WinHttp.WinHttpRequest" ascii wide nocase
        $http4 = "MSXML2.ServerXMLHTTP" ascii wide nocase
        $http5 = "http://" ascii wide nocase
        $http6 = "https://" ascii wide nocase
    // Network Indicators
        $ipv4 = /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ ascii
    // Execution
        $exec1 = "Shell" ascii wide
        $exec2 = "WScript" ascii wide
        $exec3 = "WScript.Shell" ascii wide
        $exec4 = "CreateObject" ascii wide
        $exec5 = "Adodb.Stream" ascii wide nocase
    condition:
        (2 of ($exec*, $inject*) and 1 of ($ft_*)) or
        (#ft_bmp >= 2 and $ft_jpg at 0) or
        ($ipv4 and 1 of ($http*) and 1 of ($persist*))
}

