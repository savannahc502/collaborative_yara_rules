// Needs to be tested
rule JPEG_ImageChecker
{
	meta:
		author = "Cameron"
		date = "10/06/25"
		description = "Detects JPEG formatted Files"
		filetype =  "JPEG"

	strings:
		$jpeg_header = { FF D8 FF } 
	
	condition:
		$jpeg_header at 0 

}
