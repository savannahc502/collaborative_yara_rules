param(
	[string]$Lang
)
if ($Lang -eq "php") {
	$file_folder = "C:\Users\champuser\Desktop\FOR350\Tools\Yara\Web Shell Rules\PHP"
	#$target_path = "C:\Users\champuser\Desktop\FOR350\Malware\webshells-master\php"
}elseif ($Lang -eq "perl"){
	$file_folder = "C:\Users\champuser\Desktop\FOR350\Tools\Yara\Web Shell Rules\Perl"
	#$target_path = "C:\Users\champuser\Desktop\FOR350\Malware\webshells-master\perl"
}elseif ($Lang -eq "jsp"){
	$file_folder = "C:\Users\champuser\Desktop\FOR350\Tools\Yara\Web Shell Rules\JSP"
	#$target_path = "C:\Users\champuser\Desktop\FOR350\Malware\webshells-master\jsp"
}elseif ($Lang -eq "nodejs"){
	$file_folder = "C:\Users\champuser\Desktop\FOR350\Tools\Yara\Web Shell Rules\NodeJS"
	#$target_path = "C:\Users\champuser\Desktop\FOR350\Malware\webshells-master\php"
}elseif ($Lang -eq "cmd"){
	$file_folder = "C:\Users\champuser\Desktop\FOR350\Tools\Yara\Web Shell Rules\CMD & PS"
	#$target_path = "C:\Users\champuser\Desktop\FOR350\Malware\webshells-master\php"
}elseif ($Lang -eq "asp"){
	$file_folder = "C:\Users\champuser\Desktop\FOR350\Tools\Yara\Web Shell Rules\ASP"
	#$target_path = "C:\Users\champuser\Desktop\FOR350\Malware\webshells-master\asp"
}else {
	Write-Output "Invalid Option!"
	exit
}
$target_path = "C:\Users\champuser\Desktop\FOR350\Malware\webshells-master"
Get-ChildItem -Path $file_folder -Filter "*.yar"| ForEach-Object {
echo "$_"
.\yara64.exe -r $_.FullName $target_path
}