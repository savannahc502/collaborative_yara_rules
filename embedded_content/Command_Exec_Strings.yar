rule Command_Execution_Strings {
    meta:
        description = "Detects files containing command execution strings"
        author = "Cameron"
        date = "2025-09-21"
    strings:
        $cmd1 = "cmd.exe" ascii wide nocase
        $cmd2 = "powershell.exe" ascii wide nocase
        $cmd3 = "/c " ascii wide
        $cmd4 = "-exec" ascii wide
        $cmd5 = "system(" ascii
        $cmd6 = "WinExec" ascii
        $cmd7 = "CreateProcess" ascii
    condition:
        2 of them
}
