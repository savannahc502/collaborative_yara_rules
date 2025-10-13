// Done - Need to be tested
rule BMP_ImageChecker {
    meta:
        author = "Lily Pouliot" 
        date = "10/6/2025"
        description = "Detects BMP file formats headers and other hex identifiers"
        filetype = "BMP"

    strings:
        $BMP_Header_one = "BM"
        $BMP_Header_two = { 43 4D }
        

    condition:
         $BMP_Header_one at 0 or $BMP_Header_two at 0
      
}
