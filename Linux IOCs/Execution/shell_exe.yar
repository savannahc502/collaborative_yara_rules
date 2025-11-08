rule shell_exe {
    meta:
        description = "Checks for indicators of shell execution"
        author = "Eamon Stackpole"
        editor = "N/A"
        version = "1.0"
        date = "2025-11-08"
        
    strings:
        $command1 = "fopen(" ascii
        $command2 = "fwrite(" ascii
        $command3 = "fgets(" ascii
        $command4 = "strlen(" ascii
        $shell = "/bin/bash" ascii
    condition:
       uint32(0) == 0x464c457f and
       (
          any of ($command*) and $shell
       ) 
}
