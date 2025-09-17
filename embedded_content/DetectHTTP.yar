rule DetectHTTP {
    meta:
        description = "Detects files containing any http/https URLs, Domains, and ports 8080,3389 & 22"
        author = "Connor"
        date = "2025-01-17"
    
    strings:
        $http = "http://"
        $https = "https://"
        $com = ".com"
        $net = ".net"
        $org = ".org"
        $ipv4 = /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/
        $port80 = ":80"
        $port443 = ":443"
        $port8080 = ":8080"
        $port3389 = ":3389"
        $port22 = ":22"
    
    condition:
        any of them
}
