rule svchostInRegistry {
    meta:
        description = "Rule which checks for registry keys witch C:\ProgramData\SecurityUpdate\svchost.exe"
        author = "Connor East"
        date = "10/27/25"
    
    strings:
	$key1 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsDefender"
	$key2 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SYSTEM_SERVICE"
	$value = "C:\ProgramData\SecurityUpdate\svchost.exe"

    condition:
	($key1 or $key2) and $value

}
