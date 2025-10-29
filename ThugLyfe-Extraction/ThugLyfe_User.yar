rule ThugLyfe_User {
	meta:
	description = "Detects admin accounts created by ThugLyfe"
	author = "Connor East"
	date = "2025-10-29"

	strings:
	$user1 = "administators"
	$user2 = "SYSTEM_SERVICE"
	$pass1 = "Secur1ty@2025"
	$pass2 = "SVC@Admin99"
	$cmd1 = "net user" nocase
	$cmd2 = "net localgroup Administrators" nocase

	condition:
	uint16(0) == 0x5A4D
	(
		(any of ($user*) and any of ($pass*)) or
		(all of ($cmd*) and any of ($user*))
	)
}