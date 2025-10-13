// Needs testing
rule DetectWAV{
	meta:
		description = "Detects .wav files using headers and other hex identifiers"
		author = "Connor"
		date = "2025-10-06"

	strings:
		$wav_header = { 52 49 46 46 }
		$wav_header1 = { 57 41 56 45 66 6D 74 20}
		$wav_extension = ".wav"
	
	condition:
		$wav_header at 0 or $wav_header1 at 0 or$wav_extension at 0  
}
