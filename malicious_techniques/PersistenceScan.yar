import "pe" 

{
    meta: 
      description = " Scans for common persistence techniques"
      author = "Louis Mattiolo"
      date = "9/19/25"


    strings:
        $reg1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
        $reg2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii wide
        $service1 = "CreateService" ascii wide
        $service2 = "StartService" ascii wide
        $task1 = "Task Scheduler" ascii wide
        $startup = "Startup" ascii wide
        $autorun = "autorun.inf" ascii wide nocase
        
    condition:
        uint16(0) == 0x5A4D and
        (1 of ($reg*) or 1 of ($service*) or $task1 or $startup or $autorun)
}
