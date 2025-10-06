// Needs testing
rule DetectWAV{
	meta:
		description = "Detects .wav files"
		author = "Connor"
		date = "2025-10-06"

	strings:
		$wav_header = { 52 49 46 46 }
		$wav_extension = ".wav"
	
	condition:
		$wav_header and $wav_extension
}
