rule is_JSP_Java_NetSocket {
	meta:
		description = "Detects the use of the JSP java.net.Socket function which is used for reverse/bind shells"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
		$func = "java.net.Socket"
	condition:
		$func


}