import "pe"

rule Suspicious_API_Calls {
  meta: 
      description = "Detects suspicious Windows API combinations"
        author = "Louis Mattiolo"
        date = "9/19/25"

strings:
        $api1 = "CreateRemoteThread" ascii wide
        $api2 = "WriteProcessMemory" ascii wide
        $api3 = "VirtualAllocEx" ascii wide
        $api4 = "OpenProcess" ascii wide
        $api5 = "GetProcAddress" ascii wide
        $api6 = "LoadLibrary" ascii wide
        $api7 = "SetWindowsHookEx" ascii wide

condition:
        uint16(0) == 0x5A4D and  //PE file
        3 of ($api*)  //At least 3 suspicious APIs
}
