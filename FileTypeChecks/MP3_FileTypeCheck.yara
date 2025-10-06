// Needs to be tested
rule MP3_Audio_File {
	meta:
		author = "Louis Mattiolo"
		date = "Oct 6th 2025"
		description = "Detect MP3 audio files based on headers"

strings: 

	$mp3_header1 = { FF FB } //mpeg-1 layer 3 header common mp3 format
	$mp3_header2 = { FF F3} //mpeg-2 layer 3 lower sample rate 
	$id3_tag = "ID3" ascci wide // metadata artist, title, etc 


condition: 
	any of ($mp3_header*) or $id3_tag at 0
}
