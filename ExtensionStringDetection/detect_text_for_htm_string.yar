rule detect_htm_extension {
    meta:
        author = "Savannah"
        description = "Detects presence of .htm string in file text"
        date = "2025-11-01"
        version = "1.0"
    strings:
        $ext = ".htm"
    condition:
        $ext
}
