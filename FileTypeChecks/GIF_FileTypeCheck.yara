// Needs to be tested
rule GIF_ImageChecker {
    meta:
        author = "Lily Pouliot"
        date = "10/6/2025"
        description = "Detects GIF file formats using the file header and hex"
        filetype = "GIF"

    strings:
        $GIF_Header_One = "GIF87a"
        $GIF_Header_Two = "GIF89a"
        $GIF_HEX_One = "47 49 46 38 37 61"
        $GIF_HEX_Two = "47 49 46 38 39 61"
    

    condition:
        $GIF_Header_One at 0 or  $GIF_Header_Two at 0 and 
        $GIF_HEX_One at 0 or  $GIF_HEX_Two at 0

}
