rule hostname_discovery {
    meta:
        description = "checks for indicators of account discovery"
        author = "Eamon Stackpole"
        editor = "N/A"
        version = "1.0"
        date = "2025-11-08"
        
    strings:
        $command1 = "fopen("
        $path = "/etc/passwd"
    condition:
       uint32(0) == 0x464c457f and
       (
          $command1 and $path
       ) 
}
