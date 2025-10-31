rule ASP_FileTypeCheck
{
    meta:
        description = "Detects ASP files"
        author = "Connor East"
	date = "10/31/25"

    strings:
        $asp_directive = { 3C 25 40 }
        $asp_tag = { 3C 25 }
        $asp_lang = "Language=" nocase
        $vbscript = "VBScript" nocase
        $jscript = "JScript" nocase
        
    condition:
        ($asp_directive in (0..500) or $asp_tag in (0..500)) and
        (any of ($asp_lang, $vbscript, $jscript))
}