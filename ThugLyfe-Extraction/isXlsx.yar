rule isXlsx {
    meta:
        description = "Basic rule which locates xlsWb documents"
        author = "Connor East"
        date = "10/27/25"
    
    strings:
	&xls = { 50 4b 03 }
	$xlsWb = "workbook.xml.rels"
    condition:
        $xls at 0 and
	$xlsWb in (0..896)

}
