rule shell_profile_modification {
    meta:
        description = "Checks for indicators of shell profile modification"
        author = "Eamon Stackpole"
        editor = "N/A"
        version = "1.0"
        date = "2025-11-08"
        
    strings:
        $command = "fopen(" ascii
        $persist = ".bashrc" ascii
    condition:
       uint32(0) == 0x464c457f and
       (
          $command and $persist
       ) 
}
