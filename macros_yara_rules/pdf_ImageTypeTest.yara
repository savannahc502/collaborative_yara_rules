rule pdf_ImageTypeTest
{
	meta:
		author = "Savannah Ciak"
		date = "6 October 2025"
description = "Detects PDF file format"
		filetype = "PDF"

	strings: 
		$pdf_header = "%PDF"

	condition: 
		$pdf_header at 0
}

