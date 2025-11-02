rule zip_FileTypeCheck
{
  meta:
    description = "Detects Zip packed executables"
    author = "Connor East"
    date = "2025-11-01"

  strings:
    $zip_header1 = { 50 4B 03 04 }  // PK.. (local file header)
    $zip_header2 = { 50 4B 05 06 }  // PK.. (end of central dir)
    $zip_header3 = { 50 4B 07 08 }  // PK.. (data descriptor)

  condition:
    $zip_header1 at 0 or
    $zip_header2 at 0 or
    $zip_header3 at 0
}
