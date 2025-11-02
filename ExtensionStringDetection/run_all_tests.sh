#!/bin/bash
for ext in pif lnk exe docx xlsx pptx pdf rar 7z zip dll rtf html htm; do
    yara detect_text_for_${ext}_string.yar TestTextFile.txt
done


'''
Make executable by 
chmod +x run_all_tests.sh
./run_all_tests.sh
'''
