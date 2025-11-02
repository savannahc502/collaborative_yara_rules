rule is_JSP_Runtime_GetRuntime_Exec {
	meta:
		description = "Detects the use of JSP RunTime.getRuntime(.exec( function"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
		$func = "Runtime.getRuntime().exec("
	condition:
		$func


}