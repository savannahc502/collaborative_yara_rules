rule xls_FileTypeCheck
{
    meta:
        description = "Detects XLS packed executables"
        author = "Connor East"
        date = "2025-11-01"
        
    strings:
        $xls_header = { D0 CF 11 E0 A1 B1 1A E1 }

    condition:
        $xls_header at 0
}