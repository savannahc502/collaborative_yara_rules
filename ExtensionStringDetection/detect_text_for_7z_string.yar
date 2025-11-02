rule detect_7z_extension {
    meta:
        author = "Savannah"
        description = "Detects presence of .7z string in file text"
        date = "2025-11-01"
        version = "1.0"
    strings:
        $ext = ".7z"
    condition:
        $ext
}
