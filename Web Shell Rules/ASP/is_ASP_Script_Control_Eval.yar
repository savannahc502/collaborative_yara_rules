rule is_ASP_Script_Control_Eval {
	meta:
		description = "Detects the use of the ASP ScriptControl.Eval function"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
		$func = "ScriptControl.Eval"
	condition:
		$func


}