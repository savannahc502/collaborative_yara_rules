import "hash"
import "pe"
rule ThugLyfeSecurityAdvisorDOCM {
	meta:
	description = "Locates the malicious DOCM file"
	md5 = "92910b8ec24ace49e3a6eecf3670ff57"

	condition:
	hash.md5(0, filesize) == "92910b8ec24ace49e3a6eecf3670ff57"

}