rule xlsx_FileTypeCheck
{
    meta:
        description = "Detects XLSX packed executables"
        author = "Connor East"
        date = "2025-11-01"
        
    strings:
        $xlsx_header = { 50 4B 03 04 }
        $xlsx_content = "xl/" ascii

    condition:
        $xlsx_header at 0 and $xlsx_content
}