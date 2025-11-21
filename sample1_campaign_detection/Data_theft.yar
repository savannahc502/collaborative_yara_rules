
rule Data_theft {
    meta:
        description = "Detects odd data collection"
        author = "Connor East"
        date = "11/20/2025"
        
    strings:
	$wallet1 = { 22 77 61 6c 6c 65 74 22 } // [wallet]
	$wallet2 = { 22 61 74 74 61 63 6B 61 63 6B 72 5F 77 61 6C 65 74 22 } //["attackacker_wallet"]
	$DB1 = { 2F 74 6D 70 2F 2E 63 6F 6C 6C 65 63 74 65 64 }
	$DB2 = { 2A 2E 73 71 6C 69 74 65 } // [sqlite]
    condition:
	1 of ($wallet*) and any of ($DB*)


}