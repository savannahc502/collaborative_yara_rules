rule detect_rar_extension {
    meta:
        author = "Savannah"
        description = "Detects presence of .rar string in file text"
        date = "2025-11-01"
        version = "1.0"
    strings:
        $ext = ".rar"
    condition:
        $ext
}
