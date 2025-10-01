import "pe"

rule Small_PE_File {
    meta:
        description = "Detects suspiciously small PE files"
        author = "Cameron"
        date = "2025-09-21"
    condition:
        pe.is_pe and
        filesize < 10KB and
        pe.number_of_sections > 0
}
