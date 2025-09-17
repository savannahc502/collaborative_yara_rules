import "pe" 

rule pe_magic_number {
  meta:
    description = "Searches for files that have a PE structure and flags if there if an incorrect magic number" 
	  author = "Savannah Ciak"
	  date = "2025-9-17"
  condition:
    pe.is_pe and unint16(0) != 0x5A4D // Checks that file is a PE file and if the header is not 'MZ'
}
