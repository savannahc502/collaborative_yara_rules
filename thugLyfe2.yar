rule is_Downloader2 { //image_downloader.exe
	meta:
		description = "Detects Image Downloader based on file headers, unique strings, files, and addresses"
		author = "Eamon Stackpole"
		editor = "N/A"
		date = "2025-10-09"
	strings:
		$name = "ImageDownloader/"
		$ip = "165.73.244.11"
		$image = "frontpage.jpg"
		$ft_pe = { 4D 5A }
		$ft_mp3 = { FF FB }
	condition:
		$name and 
		$ip and
		$image and
		$ft_pe at 0 and
		$ft_mp3
}

rule is_OfficeAutoOpen { //SecurityAdvisory.docm
	meta:
		description = "Detects Microsoft Office files with VBA Macros set to AutoOpen using a file header and files associated with VBA"
		author = "Eamon Stackpole"
		editor = "N/A"
		date = "2025-10-09"
	strings:    
		$zip = { 50 4B 03 04 }
		$vba_data = "vbaData.xml"
		$vba_rel = "vbaProject.bin.rels"
		$vba = "vbaProject.bin"
	condition:
		$zip at 0 and
		all of ($vba*)
}

rule is_Packed2 { //Volt.wav
	meta:
		description = "Detects Packed file using a unique string, packer headers, file headers, and file trailers"
		author = "Eamon Stackpole"
		editor = "N/A"
		date = "2025-10-09"
	strings:
		$packer = "SR"
		$ft_jpeg = { FF D8 FF }
		$tr_jpeg = { FF D9 }
		$ft_bm = { 42 4D }
		$string = "Google"
	condition:
		$string and
		$packer and
		$ft_jpeg at 0 and
		$tr_jpeg at (filesize -2) and
		$ft_bm
}