rule is_JSP_Invoke_Method {
	meta:
		description = "Detects the use of the JSP java.lang.reflect.Method.invoke( function, which is used to dynamically invoke methods on objects"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
		$func = "java.lang.reflect.Method.invoke("
	condition:
		$func



}
