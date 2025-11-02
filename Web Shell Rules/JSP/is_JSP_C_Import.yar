rule is_JSP_C_Import {
	meta:
		description = "Detects the use of JSP c:import function which is used for inclusion of URLS"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
		$func = "<c:import"
	condition:
		$func


}