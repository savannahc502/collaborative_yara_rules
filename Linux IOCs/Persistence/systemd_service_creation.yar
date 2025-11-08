rule systemd_service_creation {
    meta:
        description = "Checks for indicators of Systemd service creation"
        author = "Eamon Stackpole"
        editor = "N/A"
        version = "1.0"
        date = "2025-11-08"
        
    strings:
        $command = "fopen(" ascii
        $service = ".service" ascii
    condition:
       uint32(0) == 0x464c457f and
       (
          $command and $service
       ) 
}
