rule detect_dll_extension {
    meta:
        author = "Savannah"
        description = "Detects presence of .dll string in file text"
        date = "2025-11-01"
        version = "1.0"
    strings:
        $ext = ".dll"
    condition:
        $ext
}
