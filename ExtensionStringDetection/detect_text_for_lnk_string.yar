rule detect_lnk_extension {
    meta:
        author = "Savannah"
        description = "Detects presence of .lnk string in file text"
        date = "2025-11-01"
        version = "1.0"
    strings:
        $ext = ".lnk"
    condition:
        $ext
}
