// Needs to be tested
rule WebP_ImageChecker {
    meta:
        author = "Lily Pouliot" 
        date = "10/6/2025"
        description = "Detects WebP file formats using hex identifiers" 
        filetype = "WebP"

    strings:
        $WebP_Header_RIFF = { 52 49 46 46 }
        $WebP_Header_WEBP = { 57 45 42 50 }
        

    condition:
        $WebP_Header_RIFF at 0 and $WebP_Header_WEBP at 8
      
}
