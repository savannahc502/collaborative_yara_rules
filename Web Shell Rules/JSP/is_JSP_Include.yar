rule is_JSP_Include {
	meta:
		description = "Detects the use of JSP jsp:include function which is used for inserting another resource into a page's response"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
		$func = "jsp:include"
	condition:
		$func


}