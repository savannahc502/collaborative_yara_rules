// Needs to be tested
rule GIF_ImageChecker {
    meta:
        author = "Lily Pouliot"
        editors = "Lily Pouliot"
        date = "10/6/2025"
        description = "Detects GIF file formats using the file header"
        filetype = "GIF"

    strings:
        $GIF_Header_One = "GIF87a"
        $GIF_Header_Two = "GIF89a"
    

    condition:
        $GIF_Header_One or  $GIF_Header_Two at 0

}
