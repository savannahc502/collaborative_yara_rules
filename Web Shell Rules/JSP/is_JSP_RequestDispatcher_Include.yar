rule is_JSP_RequestDispatcher_Include {
	meta:
		description = "Detects the use of JSP request.getRequestDispatcher(.include( function "
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
		$func = "request.getRequestDispatcher(.include("
	condition:
		$func


}