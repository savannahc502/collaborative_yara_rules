rule detect_rtf_extension {
    meta:
        author = "Savannah"
        description = "Detects presence of .rtf string in file text"
        date = "2025-11-01"
        version = "1.0"
    strings:
        $ext = ".rtf"
    condition:
        $ext
}
