
rule Data_exfiltration {
    meta:
        description = "Detects odd exfiltration methods."
        author = "Connor East"
        date = "11/20/2025"
        
    strings:
	$exfil1 = { 68 74 74 70 3A 2F 2F 61 74 74 61 63 6B 65 72 2E 63 6F 6D 3A 38 30 38 30 2F 65 78 66 69 6C } // [http:'/'/attacker.com:8080/exfil]
	$transferedfile = { 40 2F 74 6D 70 2F 2E 63 6F 6C 6C 65 63 74 65 64 } // [@/tmp/.collected]
	$method = { 62 61 63 75 72 6C 20 2D 58 20 50 4F 53 54 20 } // [bacurl -X POST]

    condition:
	all of them

}