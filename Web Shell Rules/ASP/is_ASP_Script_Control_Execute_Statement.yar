rule is_ASP_Script_Control_Execute_Statement {
	meta:
		description = "Detects the use of the ASP ScriptControl.ExecuteStatement function"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
		$func = "ScriptControl.ExecuteStatement"
	condition:
		$func


}