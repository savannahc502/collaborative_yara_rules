rule THUGLyfe_ST {
	meta:
	description = "ThugLyfe Scheduled Task"
	author = "Connor East"
	date = "2025-10-29"

	strings:
	$task_name = "WindowsUpdateCheck" nocase
	$task_cmd = "schtasks /create" nocase
	$task_path = "C:\\ProgramData\\SecurityUpdate\\svchost.exe" nocase
	$task_trigger = "/sc onlogon" nocase
	$task_priv = "/rl HIGHEST"

	condition:
	unit16(0) == 0x5A4D and
	(
		($task_name and $task_cmd) or
		($task_path and $task_cmd and ($task_priv or $task_trig))
	)
}