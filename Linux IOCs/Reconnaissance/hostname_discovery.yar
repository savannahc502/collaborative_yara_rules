rule hostname_discovery {
    meta:
        description = "Checks for indicators of hostname discovery"
        author = "Eamon Stackpole"
        editor = "N/A"
        version = "1.0"
        date = "2025-11-08"
        
    strings:
        $command1 = "gethostname(" ascii
    condition:
       uint32(0) == 0x464c457f and
       (
          $command1
       ) 
}
