
rule Sample1_All_Suspicious_Indicators {
    meta:
        description = "Detects Sample1 malware by all suspicious indicators"
        author = "Connor East"
        date = "11/20/2025"
        severity = "critical"
        malware_family = "XMRig Cryptominer with Data Theft"
        
    strings:
        // === MINING INDICATORS ===
        $mining1 = { 2F 74 6D 70 2F 2E 78 6D 72 69 67 } // /tmp/.xmrig
        $mining2 = { 2F 6F 70 74 2F 2E 78 6D 72 } // /opt/.xmr
        $mining3 = { 70 6F 6F 6C 2E 6D 69 6E 65 78 6D 72 2E 63 6F 6D } // pool.minexmr.com
        $mining4 = { 3A 34 34 34 34 } // :4444 (mining port)
        $mining5 = { 6D 69 6E 65 72 } // miner
        $mining6 = { 77 61 6C 6C 65 74 } // wallet
        
        // === PERSISTENCE INDICATORS ===
        $persist1 = { 63 72 6F 6E 74 61 62 } // crontab
        $persist2 = { 40 72 65 62 6F 6F 74 } // @reboot
        $persist3 = { 30 20 2A 20 2A 20 2A 20 2A } // 0 * * * * (hourly cron)
        
        // === HIDDEN DIRECTORIES ===
        $hidden1 = { 6D 6B 64 69 72 20 2D 70 } // mkdir -p
        $hidden2 = { 2F 74 6D 70 2F 2E } // /tmp/.
        $hidden3 = { 2F 6F 70 74 2F 2E } // /opt/.
        $hidden4 = { 32 3E 2F 64 65 76 2F 6E 75 6C 6C } // 2>/dev/null
        
        // === DATA COLLECTION ===
        $collect1 = { 2F 74 6D 70 2F 2E 63 6F 6C 6C 65 63 74 65 64 } // /tmp/.collected
        $collect2 = { 2A 2E 73 71 6C 69 74 65 } // *.sqlite
        $collect3 = { 2F 2E 6D 6F 7A 69 6C 6C 61 } // /.mozilla
        $collect4 = { 2F 2E 63 6F 6E 66 69 67 2F 67 6F 6F 67 6C 65 } // /.config/google
        $collect5 = { 2F 2E 62 61 73 68 5F 68 } // /.bash_h (bash history)
        
        // === ROOTKIT INDICATORS ===
        $rootkit1 = { 4C 44 5F 50 52 45 4C 4F 41 44 } // LD_PRELOAD
        $rootkit2 = { 72 6F 6F 74 6B 69 74 } // rootkit
        $rootkit3 = { 5B 6B 77 6F 72 6B 65 72 2F } // [kworker/ (process masquerade)
        $rootkit4 = { 2F 74 6D 70 2F 2E 72 6F 6F 74 6B 69 74 } // /tmp/.rootkit
        
        // === EXFILTRATION ===
        $exfil1 = { 63 75 72 6C } // curl
        $exfil2 = { 2D 58 20 50 4F 53 54 } // -X POST
        $exfil3 = { 61 74 74 61 63 6B 65 72 } // attacker
        $exfil4 = { 2F 74 6D 70 2F 2E 63 61 6C 6C 62 61 63 6B } // /tmp/.callback
        
        // === EXECUTION ===
        $exec1 = { 63 68 6D 6F 64 20 2B 78 } // chmod +x
        $exec2 = { 2F 62 69 6E 2F 62 61 73 68 } // /bin/bash
        $exec3 = { 23 21 2F 62 69 6E 2F 62 } // #!/bin/b (shebang)
        
        // === FILE HEADER ===
        $elf = { 7F 45 4C 46 } // ELF header
        
    condition:
        $elf at 0 and
        (
            // HIGH CONFIDENCE: Mining + Persistence
            (2 of ($mining*) and 1 of ($persist*)) or
            
            // HIGH CONFIDENCE: Mining + Hidden directories
            (2 of ($mining*) and 2 of ($hidden*)) or
            
            // HIGH CONFIDENCE: Data collection + Exfiltration
            (2 of ($collect*) and 1 of ($exfil*)) or
            
            // CRITICAL: Rootkit indicators
            (2 of ($rootkit*)) or
            
            // MEDIUM: Multiple suspicious categories
            (1 of ($mining*) and 1 of ($persist*) and 1 of ($hidden*)) or
            (1 of ($collect*) and 1 of ($hidden*) and 1 of ($exec*))
        )
}