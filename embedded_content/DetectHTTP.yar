rule DetectHTTP {
    meta:
        description = "Detects files containing any http/https URLs, Domains"
        author = "Connor East"
        date = "2025-01-17"
    
    strings:
        $http = "http://"
        $https = "https://"
        $com = ".com"
        $net = ".net"
        $org = ".org"
        $ipv4 = /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/
    
    condition:
        any of ($*)
}



