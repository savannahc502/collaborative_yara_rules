rule detect_zip_extension {
    meta:
        author = "Savannah"
        description = "Detects presence of .zip string in file text"
        date = "2025-11-01"
        version = "1.0"
    strings:
        $ext = ".zip"
    condition:
        $ext
}
