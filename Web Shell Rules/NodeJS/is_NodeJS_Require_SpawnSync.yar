rule is_NodeJS_Require_SpawnSync {
	meta:
		description = "Detects the use of NodeJS require('child_process').spawnSync( function"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "11/1/2025"
	strings:
		$func = "require('child_process').spawnSync("
	condition:
		$func


}