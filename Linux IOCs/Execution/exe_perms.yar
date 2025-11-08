rule exe_perms {
    meta:
        description = "Checks for indicators of execution permissions"
        author = "Eamon Stackpole"
        editor = "N/A"
        version = "1.0"
        date = "2025-11-08"
        
    strings:
        $command = "chmod" ascii
        $perms = "0755" ascii
    condition:
       uint32(0) == 0x464c457f and
       (
          $command and $perms
       ) 
}
