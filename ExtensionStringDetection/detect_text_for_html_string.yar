rule detect_html_extension {
    meta:
        author = "Savannah"
        description = "Detects presence of .html string in file text"
        date = "2025-11-01"
        version = "1.0"
    strings:
        $ext = ".html"
    condition:
        $ext
}
