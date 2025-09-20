import "pe" 

{
    meta:
        description = "Basic suspicious file operations"
        author = "Louis Mattiolo"
        editor = "Savannah Ciak"
        date= "9/19/25"

   strings:
        $file1 = "DeleteFile" ascii wide nocase
        $file2 = "CopyFile" ascii wide nocase
        $file3 = "MoveFile" ascii wide nocase
        $file4 = "CreateFile" ascii wide nocase
        $file5 = "WriteFile" ascii wide nocase
        $file6 = "ReadFile" ascii wide nocase
        $temp = "temp" ascii wide nocase nocase
        $system32 = "system32" ascii wide nocase
        
    condition:
        uint16(0) == 0x5A4D and
        3 of ($file*) and ($temp or $system32)
}
