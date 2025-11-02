rule EPUB_FileTypeCheck
{
    meta:
        description = "Detects EPUB ebook files"
        author = "Connor East"
	date = "10/31/25"

    strings:
        $zip = { 50 4B 03 04 }
        $mimetype = "mimetypeapplication/epub+zip"
        
    condition:
        $zip at 0 and $mimetype at 30
}