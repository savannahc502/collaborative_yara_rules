rule detect_docx_extension {
    meta:
        author = "Savannah"
        description = "Detects presence of .docx string in file text"
        date = "2025-11-01"
        version = "1.0"
    strings:
        $ext = ".docx"
    condition:
        $ext
}
