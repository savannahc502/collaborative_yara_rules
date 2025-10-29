import "hash"
import "pe"
rule ThugLyfeFrontPageJPG {
	meta:
	description = "Locates the malicious frontpage.jpg items using md5 hash"
	md5 = "6a2366799b5474a70e782666fb074e9f"

	condition:
	hash.md5(0, filesize) == "6a2366799b5474a70e782666fb074e9f"

}