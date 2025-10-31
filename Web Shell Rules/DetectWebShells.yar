
rule PHP_WebShell {
	meta:
		description = "Detects commands associated with PHP web shells"
		author = "Eamon Stackpole"
		version = "1.0"
		date = "10/31/2025"
	strings:
		//$tag = "<?php"
		$php1 = "eval("
		$php2 = "assert("
		$php3 = "create_function("
		$php4 = "preg_replace(" //incorpate /e condition
		$php5 = "include("
		$php6 = "require("
		$php7 = "include_once("
		$php8 = "require_once("
		$php9 = "system("
		$php10 = "exec("
		$php11 = "shell_exec("
		$php12 = "passthru("
		$php13 = "proc_open("
		$php14 = "popen("
		$php15 = "dl("
		$php16 = "escapeshellcmd("
		$php17 = "escapeshellarg("
		$php18 = "base64_decode("
		$php19 = "gzinflate("
		$php20 = "urldecode("
		$php21 = "file_get_contents("
		$php22 = "fopen("
		$php23 = "fwrite("
		$php24 = "copy("
		$php25 = "move_uploaded_file("
		
	condition:
		//$tag and 
		any of ($php*)

}
rule Perl_WebShell {
	meta:
		description = "Detects commands associated with Perl web shells"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "10/31/2025"
	strings:
		//$tag = "#!/usr/bin/perl"
		$perl1 = "system("
		$perl2 = "exec("
		$perl3 = "open(" // with pipe (e.g., open(FILE, "command|"))
		$perl4 = "backticks"
		$perl5 = "eval("
		$perl6 = "require("
		$perl7 = "do("
		$perl8 = "use("
		$perl9 = "readpipe("
		$perl10 = "fork(" //combined with exec(
		$perl11 = "socket("
		$perl12 = "IO::Socket"

	condition:
		//$tag and 
		any of ($perl*)

}
rule ASP_WebShell {
	meta:
		description = "Detects commands associated with ASP, VBScript, web shells"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "10/31/2025"
	strings:
		$asp1 = "Execute("
		$asp2 = "Eval("
		$asp3 = "GetObjectContext("
		$asp4 = "Server.CreateObject(\"WScript.Shell\")"
		$asp5 = "Server.CreateObject(\"Shell.Application\")"
		$asp6 = "Server.CreateObject(\"ADODB.Stream\")"
		$asp7 = "Server.Execute("
		$asp8 = "Response.Write("
		$asp9 = "ScriptControl.Eval"
		$asp10 = "ScriptControl.ExecuteStatement"
		$asp11 = "Server.MapPath("
	condition:
		any of ($asp*)

}
rule NodeJS_WebShell {
	meta:
		description = "Detects commands associated with NodeJS web shells"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "10/31/2025"
	strings:
		$node1 = "require('child_process').exec("
		$node2 = "require('child_process').execSync("
		$node3 = "require('child_process').spawn("
		$node4 = "require('child_process').spawnSync("
		$node5 = "require('child_process').execFile("
		$node6 = "require('child_process').execFileSync("
		$node7 = "eval("
		$node8 = "global.eval("
		$node9 = "require('vm').runInThisContext("
		$node10 = "require('vm').runInNewContext("
		$node11 = "require('fs').writeFile("
		$node12 = "require('fs').writeFileSync("
		$node13 = "require('fs').readFile("
		$node14 = "require('fs').readFileSync("
		$node15 = "require('fs').createWriteStream("
		$node16 = "require('http').createServer("  //NOTE(used for reverse shell)
		$node17 = "require('net').Socket"  //NOTE: (for outbound connections)
	condition:
		any of ($node*)

}
rule JSP_WebShell {
	meta:
		description = "Detects commands associated with JSP web shells"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "10/31/2025"
	strings:
		$jsp1 = "Runtime.getRuntime(.exec("
		$jsp2 = "ProcessBuilder.start("
		$jsp3 = "java.lang.reflect.Method.invoke("
		$jsp4 = "javax.script.ScriptEngine.eval("
		$jsp5 = "Class.forName(.getMethod(.invoke("
		$jsp6 = "jsp:include"
		$jsp7 = "c:import (JSTL)"
		$jsp8 = "pageContext.include("
		$jsp9 = "request.getRequestDispatcher(.include("
		$jsp10 = "ClassLoader.defineClass("
		$jsp11 = "new java.io.FileOutputStream("
		$jsp12 = "new java.io.PrintWriter("
		$jsp13 = "java.net.Socket" // (for reverse/bind shells)
		$jsp14 = "javax.servlet.jsp.JspWriter.print("
		$jsp15 = "System.setIn(, System.setOut(, System.setErr("   //NOTE: (for stream manipulation)

	condition:
		any of ($jsp*)

}
rule CommandLine_Shell {
	meta:
		description = "Detects commands associated with CMD and Powershell command line shells"
		author = "Eamon Stackpole"
		editor = "N/A"
		version = "1.0"
		date = "10/31/2025"
	strings:
		$cmd1 = "cmd.exe /c"
		$cmd2 = "cmd /c"
		$ps1 = "powershell.exe"
		$ps2 = "powershell"
	condition:
		any of ($ps*) or 
		any of ($cmd*)

}