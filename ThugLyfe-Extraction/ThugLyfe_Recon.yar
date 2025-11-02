rule ThugLyfe_Recon {
	meta:
	description = "Detects system reconnaissance commands"
	author = "Connor East"
	date = "25-10-29"
	
	strings:
	$cmd1 = "systeminfo /fo csv" nocase 
	$cmd2 = "netsh interface show interface" nocase
	$cmd3 = "ipconfig /displaydns" nocase
	$cmd4 = "netstat -anob" nocase
	$cmd5 = "wmic useraccount get name,sid" nocase
	$cmd6 = "sc query type= service state= all" nocase
	$cmd7 = "schtasks /query /fo CSV /v" nocase
	$comment = "REM automated system optimization" nocase

	condition:
	uint16(0) == 0x5A4D and
	(
		(4 of ($cmd*)) or
		($comment and 3 of ($cmd*))
	)



}