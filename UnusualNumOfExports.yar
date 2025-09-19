import "pe"

rule UnusualNumOfExports {
	meta:
		description = "Detects if files exports an unusual amount of functions"
		author = "Eamon Stackpole"
		date = "9/19/2025"
	condition:
		pe.number_of_exports < 5 or pe.number_of_exports > 10


}