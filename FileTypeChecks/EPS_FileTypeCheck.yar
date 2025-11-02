rule EPS_FileTypeCheck
{
  meta:
    description = "Detects Encapsulated PostScript files"
    author = "Connor East"
    date = "2025-10-31"

  strings:
    $ps  = { 25 21 50 53 2D 41 64 6F 62 65 }  // %!PS-Adobe
    $eps = { 45 50 53 46 }                    // EPSF

  condition:
    $ps at 0 and $eps
}
