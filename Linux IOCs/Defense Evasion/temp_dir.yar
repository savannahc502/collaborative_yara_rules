rule temp_dir {
    meta:
        description = "Checks for indicators of temporary directories use"
        author = "Eamon Stackpole"
        editor = "N/A"
        version = "1.0"
        date = "2025-11-08"
        
    strings:
        $command1 = "fopen(" ascii
        $command2 = "fwrite(" ascii
        $dir1 = "/tmp" ascii
        $dir2 = "/var/tmp" ascii
        $dir3 = "/dev/shm" ascii
    condition:
       uint32(0) == 0x464c457f and
       (
          any of ($command*) and
          any of ($dir*)
       ) 
}
