rule is_JSP_ClassLoader_DefineClass {
	meta:
		description = "Detects the use of the JSP ClassLoader.defineClass( function "
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
		$func = "ClassLoader.defineClass("
	condition:
		$func



}
