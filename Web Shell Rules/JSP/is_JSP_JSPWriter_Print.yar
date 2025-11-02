rule is_JSP_JSPWriter_Print {
	meta:
		description = "Detects the use of the JSP javax.servlet.jsp.JspWriter.print( function "
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
		$func = "javax.servlet.jsp.JspWriter.print("
	condition:
		$func


}