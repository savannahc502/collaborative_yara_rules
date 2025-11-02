import "hash"
import "pe"
rule ThugLyfeFakeSvchostMD5 {
	meta:
	description = "Detects the malicious MD5 hash"
	md5 = "5207fe630502c3ff2515dd49683c9b2e"

	condition:
	hash.md5(0, filesize) == "5207fe630502c3ff2515dd49683c9b2e"

}