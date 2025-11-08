rule shadow_file_access {
    meta:
        description = "Checks for indicators of shadow file access"
        author = "Eamon Stackpole"
        editor = "N/A"
        version = "1.0"
        date = "2025-11-08"
        
    strings:
        $command = "fopen(" ascii
        $path = "/etc/shadow" ascii
    condition:
       uint32(0) == 0x464c457f and
       (
          $command and $path
       ) 
}
