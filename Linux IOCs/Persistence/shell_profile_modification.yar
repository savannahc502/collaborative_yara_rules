rule shell_profile_modification {
    meta:
        description = "Checks for indicators of Cron Job creation"
        author = "Eamon Stackpole"
        editor = "N/A"
        version = "1.0"
        date = "2025-11-08"
        
    strings:
        $command1 = "fopen(" ascii
        $command2 = "fwrite(" ascii
        $persist = "@reboot" ascii
    condition:
       uint32(0) == 0x464c457f and
       (
          $command1 and
          ($command2 and $persist)
       ) 
}
