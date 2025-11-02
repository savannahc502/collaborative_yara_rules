rule is_JSP_PageContext_Include {
	meta:
		description = "Detects the use of JSP pageContext.include( function "
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
		$func = "pageContext.include("
	condition:
		$func


}