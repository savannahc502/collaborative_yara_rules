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

condition: 
   uint17(0) == 0x54AD and 
   (1 of ($reg*) or 1 of ($service*)

}
