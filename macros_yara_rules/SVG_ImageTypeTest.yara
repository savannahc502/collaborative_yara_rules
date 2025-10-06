rule SVG_ImageTypeTest
{
	meta:
		author = "Savannah Ciak"
		date = "6 October 2025"
    description = "Detects SVG file format"
		filetype = "SVG"

	strings: 
		$svg_tag = "<svg"

	condition: 
		$svg_tag
}
