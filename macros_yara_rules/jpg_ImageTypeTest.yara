rule JPG_ImageTypeTest
{
	meta:
		author = "Savannah Ciak"
		date = "6 October 2025"
		description = "Detects JPG file format using hex headers"
		filetype = "JPG"

	strings: 
		$jpg_magic = { FF D8 FF }

	condition: 
		for any i in (0..1024) : ($jpg_magic at i)
		// This checks for FF D8 FF anywhere in the first 1024 bytes.
}
