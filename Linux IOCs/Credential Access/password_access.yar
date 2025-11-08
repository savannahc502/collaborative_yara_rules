rule password_access {
    meta:
        description = "Checks for indicators of password file access"
        author = "Eamon Stackpole"
        editor = "N/A"
        version = "1.0"
        date = "2025-11-08"
        
    strings:
        $command1 = "fopen(" ascii
        $command2 = "fwrite(" ascii
        $path1 = "/etc/passwd" ascii
        $path2 = "/etc/shadow" ascii
    condition:
       uint32(0) == 0x464c457f and
       (
        any of ($command*) and any of ($path*)
       ) 
}
