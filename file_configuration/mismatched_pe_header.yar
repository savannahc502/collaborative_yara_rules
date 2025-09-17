import "pe" 

rule pe_magic_number {
  meta:
    description = "searches for files that have a PE structure and flags if there if an incorrect magic number" 
	  author = "Savannah Ciak"
	  date = "2025-9-17"
  condition:
    pe.is_pe and unint16(0) != 0x5A4D // 'MZ' header
}
