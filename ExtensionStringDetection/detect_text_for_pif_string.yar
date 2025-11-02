rule detect_pif_extension {
    meta:
        author = "Savannah"
        description = "Detects presence of .pif string in file text"
        date = "2025-11-01"
        version = "1.0"
    strings:
        $ext = ".pif"
    condition:
        $ext
}
