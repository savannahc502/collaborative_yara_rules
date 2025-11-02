@echo off
for %%E in (pif lnk exe docx xlsx pptx pdf rar 7z zip dll rtf html htm) do (
    "C:\Users\champuser\Downloads\ExtensionStringDetection\yara64.exe" detect_text_for_%%E_string.yar TestTextFile.txt
)
