rule ListPdf
{
    strings:
        $pdf_header = { 25 50 44 46 }
        $pdf_header_text = "%PDF-"
        $pdf_eof = "%%EOF"
    condition:
        ($pdf_header at 0 or $pdf_header_text at 0) and $pdf_eof
}
