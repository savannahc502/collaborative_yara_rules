rule detect_pptx_extension {
    meta:
        author = "Savannah"
        description = "Detects presence of .pptx string in file text"
        date = "2025-11-01"
        version = "1.0"
    strings:
        $ext = ".pptx"
    condition:
        $ext
}
