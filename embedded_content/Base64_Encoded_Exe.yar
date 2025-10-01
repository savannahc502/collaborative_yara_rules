rule Base64_Encoded_PE {
    meta:
        description = "Detects Base64 encoded PE file patterns"
        author = "Cameron"
        date = "2025-09-21"
    strings:
        // Base64 encoded "MZ" header
        $b64_mz1 = "TVqQ" ascii
        $b64_mz2 = "TVpQ" ascii
        $b64_mz3 = "TVoA" ascii
        $b64_mz4 = "TVpB" ascii
        // Base64 encoded "This program"
        $b64_this = "VGhpcyBwcm9ncmFt" ascii
    condition:
        any of them
}
