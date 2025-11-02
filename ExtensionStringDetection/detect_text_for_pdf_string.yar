rule detect_pdf_extension {
    meta:
        author = "Savannah"
        description = "Detects presence of .pdf string in file text"
        date = "2025-11-01"
        version = "1.0"
    strings:
        $ext = ".pdf"
    condition:
        $ext
}
