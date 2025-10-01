rule ListPdf
{
    meta:
        description = "Lists PDF's containing a valid PDF header and EOF marker"
        author = "Connor East and Savannah Ciak"
        date = "2025-01-17"

    strings:
        $pdf_header = { 25 50 44 46 }
        $pdf_header_text = "%PDF-"
        $pdf_eof = "%%EOF"
    condition:
        ($pdf_header at 0 or $pdf_header_text in(0..1024)) and $pdf_eof
        // Since some PDFs have junk at the start of the file, this searches for PDF headers within the first 1KB.
}

