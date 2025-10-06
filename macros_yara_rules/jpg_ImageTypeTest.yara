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
		$jpg_magic at 0
}
