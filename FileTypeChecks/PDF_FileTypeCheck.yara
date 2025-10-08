rule pdf_ImageTypeTest
{
	meta:
		author = "Savannah Ciak"
		date = "6 October 2025"
		description = "Detects PDF file format using headers"
		filetype = "PDF"

	strings: 
		$pdf_header = "%PDF"

	condition: 
		for any i in (0..1024) : ($pdf_header at i)
		// This checks for %PDF anywhere in the first 1024 bytes.
}

