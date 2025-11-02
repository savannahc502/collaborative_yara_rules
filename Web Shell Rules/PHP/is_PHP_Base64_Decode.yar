rule is_PHP_Base64_Decode {
	meta:
		description = "Detects the use of the PHP base64_decode function"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
	    $func = "base64_decode("
	condition:
      $func

}
