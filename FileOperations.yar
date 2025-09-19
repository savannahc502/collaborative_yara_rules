import "pe" 

{
    meta:
        description = "Basic suspicious file operations"
        author = "Louis Mattiolo"
        date= "9/19/25"

   strings:
        $file1 = "DeleteFile" ascii wide
        $file2 = "CopyFile" ascii wide
        $file3 = "MoveFile" ascii wide
        $file4 = "CreateFile" ascii wide
        $file5 = "WriteFile" ascii wide
        $file6 = "ReadFile" ascii wide
        $temp = "temp" ascii wide nocase
        $system32 = "system32" ascii wide nocase
        
    condition:
        uint16(0) == 0x5A4D and
        3 of ($file*) and ($temp or $system32)
}
