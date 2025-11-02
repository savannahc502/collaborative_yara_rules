rule is_JSP_ScriptEngine_Eval {
	meta:
		description = "Detects the use of JSP javax.script.ScriptEngine.eval function which is used for the execution of scripts"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
		$func = "javax.script.ScriptEngine.eval("
	condition:
		$func


}