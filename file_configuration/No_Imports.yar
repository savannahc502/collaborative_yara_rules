import "pe"

rule No_Imports {
    meta:
        description = "Detects PE files with no import table"
        author = "Cameron"
        date = "2025-09-21"
    condition:
        pe.is_pe and
        pe.number_of_imports == 0
}
