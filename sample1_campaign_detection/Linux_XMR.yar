rule Linux_XMR {
    meta:
        description = "Detects .XMR Malware"
        author = "Connor East"
        date = "11/20/2025"
        
    strings:
        $XMR1 = { 2F 74 6D 70 2F 2E 78 6D 72 69 67 2F } // [/tmp/.xmrig/]
	$XMR2 = { 2F 74 6D 70 2F 2E 78 6D 72 69 67 2F 6D 69 6E 65 72 } // [/tmp/.xmrig/miner]
	$Web1 = { 6E 65 78 6D 72 2E 63 6F 6D 3A 34 34 34 34 } // [nexmr.com:4444]
	$Web2 = { 70 6F 6F 6C 2E 6D 69 6E 65 78 6D 72 2E 63 6F 6D } // [pool.minexmr.com]
        
    condition:
	1 of ($XMR*) and any of ($Web*)
}