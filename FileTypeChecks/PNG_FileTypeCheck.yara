rule PNG_Checker
{
	meta:
		author = "Cameron"
		date = "10/06/25"
		description = "Detects PNG  using  hex identifiers"
		filetype =  "PNG"

	strings:
		$png_header = { 89 50 4E 47 0D 0A 1A 0A }

	condition: 
		$png_header at 0

}
