rule detect_exe_extension {
    meta:
        author = "Savannah"
        description = "Detects presence of .exe string in file text"
        date = "2025-11-01"
        version = "1.0"
    strings:
        $ext = ".exe"
    condition:
        $ext
}
