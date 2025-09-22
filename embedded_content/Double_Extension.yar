rule Executable_With_Double_Extension {
    meta:
        description = "Detects files trying to hide executable nature"
        author = "Cameron"
        date = "2025-09-21"
    strings:
        $double1 = ".pdf.exe" ascii wide nocase
        $double2 = ".doc.exe" ascii wide nocase
        $double3 = ".jpg.exe" ascii wide nocase
        $double4 = ".txt.exe" ascii wide nocase
        $double5 = ".docx.exe" ascii wide nocase
        $double6 = ".xlsx.exe" ascii wide nocase
    condition:
        any of them
}
