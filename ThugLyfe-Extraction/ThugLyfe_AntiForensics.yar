rule ThugLyfe_AntiForensics {
	meta:
	description = "detects ant-forensics commands"
	author = "Connor East"
	date = "2025-10-29"

	strings
	$cmd1 = "wevtutil cl Security" nocase
	$cmd2 = "wevtutil cl System" nocase
	$cmd3 = "wevtutil cl Application" nocase
	$cmd4 = "del /F /Q %APPDATA%\\Microsoft\\Windows\\Recent" nocase
	$empty = ">nul 2>&1"

	condition:
	uint16(0) == 0x5A4D and
	(
		(2 of ($cmd*) and $empty) or
		(3 of ($cmd*))
	)


}