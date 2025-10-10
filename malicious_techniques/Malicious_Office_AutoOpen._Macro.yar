rule Malicious_Office_AutoOpen_Macro {
    meta:
        description = "Detects Office documents with VBA macros - potential malware delivery mechanism"
        author = "Cameron Jalbert + Louis Mattiolo"
        date = "2025-10-09"
    strings:
        $zip = { 50 4B 03 04 }
        $vba = "vbaProject.bin"
        $vba_rel = "vbaProject.bin.rels"
        $vba_data = "vbaData.xml"
        $word_macro = "word/vbaProject"
    condition:
        $zip at 0 and
        2 of ($vba, $vba_rel, $vba_data, $word_macro)
}
