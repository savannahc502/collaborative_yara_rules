import "pe" 

rule upx_packed {
  meta:
		description = "Detects files with UPX packing"
		author = "Savannah"
    credit = "Duane Dunston, class demo"
		date = "2025-9-17"
  strings: 
    $upx1 = "UPX0"
    $upx2 = "UPX1"
  condition: 
    any of ($upx*)
}
