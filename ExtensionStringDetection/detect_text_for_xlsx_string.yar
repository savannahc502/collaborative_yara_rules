rule detect_xlsx_extension {
    meta:
        author = "Savannah"
        description = "Detects presence of .xlsx string in file text"
        date = "2025-11-01"
        version = "1.0"
    strings:
        $ext = ".xlsx"
    condition:
        $ext
}
