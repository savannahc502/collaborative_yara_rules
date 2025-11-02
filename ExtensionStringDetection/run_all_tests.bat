@echo off
for %%E in (pif lnk exe docx xlsx pptx pdf rar 7z zip dll rtf html htm) do (
    yara64 detect_text_for_%%E_string.yar TestTextFile.txt
)
