rule zip_FileTypeCheck
{
    meta:
        description = "Detects Zip packed executables"
        author = "Connor East"
        date = "2025-11-01"
        
    strings:
        $zip_header1 = { 50 4B 03 04 }
        $zip_header2 = { 50 4B 05 06 }
        $zip_header3 = { 50 4B 07 08 }

    condition:
        ($zip_header1 or $zip_header2 or $zip_header3) at 0
}