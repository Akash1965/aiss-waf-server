/*
 * AISS YARA Rules — Web Shell Detection
 * Covers PHP, JSP, ASP, Python, Perl, and obfuscated variants
 */

rule WebShell_PHP_Generic {
    meta:
        description = "Detects generic PHP web shell execution patterns"
        severity    = "CRITICAL"
        cve_ref     = "CWE-78"
    strings:
        $exec1  = "system("        ascii nocase
        $exec2  = "shell_exec("    ascii nocase
        $exec3  = "passthru("      ascii nocase
        $exec4  = "exec("          ascii nocase
        $exec5  = "popen("         ascii nocase
        $exec6  = "proc_open("     ascii nocase
        $obfus1 = "str_rot13"      ascii nocase
        $obfus2 = "gzuncompress"   ascii nocase
        $obfus3 = "gzinflate"      ascii nocase
        $obfus4 = "base64_decode"  ascii nocase
        $eval   = "eval("          ascii nocase
        $b64php = "PD9waH"         ascii   // Base64 for "<?ph"
        $phpopen = "<?php"         ascii nocase
    condition:
        $b64php or
        ($phpopen and $eval and any of ($obfus*)) or
        ($phpopen and 2 of ($exec*))
}

rule WebShell_PHP_C99_R57 {
    meta:
        description = "Detects C99 and r57 PHP web shell fingerprints"
        severity    = "CRITICAL"
    strings:
        $c99_1  = "c99shell"       ascii nocase
        $c99_2  = "C99 Shell"      ascii
        $r57_1  = "r57shell"       ascii nocase
        $r57_2  = "r57 shell"      ascii nocase
        $sig1   = "FilesMan"       ascii
        $sig2   = "WSO "           ascii
        $sig3   = "b374k"          ascii
    condition:
        any of them
}

rule WebShell_PHP_Obfuscated_Eval {
    meta:
        description = "Detects eval-based PHP obfuscation used in web shells"
        severity    = "HIGH"
    strings:
        $eval_b64     = /eval\s*\(\s*base64_decode\s*\(/   ascii nocase
        $eval_gzip    = /eval\s*\(\s*gzinflate\s*\(/       ascii nocase
        $eval_rot     = /eval\s*\(\s*str_rot13\s*\(/       ascii nocase
        $eval_assert  = /assert\s*\(\s*base64_decode\s*\(/ ascii nocase
    condition:
        any of them
}

rule WebShell_JSP_Generic {
    meta:
        description = "Detects JSP web shell execution patterns"
        severity    = "CRITICAL"
    strings:
        $rt1  = "Runtime.getRuntime().exec("  ascii
        $rt2  = "ProcessBuilder"              ascii
        $rt3  = "getInputStream"              ascii
        $rt4  = "new ProcessBuilder"          ascii
    condition:
        $rt1 or ($rt2 and $rt3) or ($rt4 and $rt3)
}

rule WebShell_ASP_Generic {
    meta:
        description = "Detects ASP/ASPX web shell patterns"
        severity    = "CRITICAL"
    strings:
        $cmd1 = "cmd.exe"                    ascii nocase
        $cmd2 = "wscript.shell"              ascii nocase
        $cmd3 = "CreateObject(\"WScript"     ascii nocase
        $cmd4 = "Shell.Application"          ascii nocase
        $exec = "Execute("                   ascii nocase
    condition:
        ($exec and any of ($cmd*)) or
        ($cmd2 and $cmd1)
}

rule WebShell_Python_Generic {
    meta:
        description = "Detects Python-based web shell or reverse shell code"
        severity    = "CRITICAL"
    strings:
        $import_os    = "import os"          ascii
        $import_sub   = "import subprocess"  ascii
        $os_system    = "os.system("         ascii
        $popen        = "subprocess.Popen("  ascii
        $socket_conn  = "socket.connect("    ascii
        $bind_shell   = "bind_shell"         ascii nocase
        $reverse      = "reverse_shell"      ascii nocase
    condition:
        ($os_system or $popen) and ($import_os or $import_sub) or
        ($socket_conn and ($bind_shell or $reverse))
}

rule WebShell_Perl_Generic {
    meta:
        description = "Detects Perl-based web shell patterns"
        severity    = "CRITICAL"
    strings:
        $use_socket   = "use Socket"         ascii
        $exec1        = "exec(\"/bin/sh"     ascii
        $exec2        = "system(\"/bin/sh"   ascii
        $backtick     = /`[^`]{0,200}`/      ascii
    condition:
        ($use_socket and ($exec1 or $exec2)) or
        $backtick
}

rule WebShell_Generic_Reverse_Shell {
    meta:
        description = "Detects generic reverse shell connection patterns"
        severity    = "CRITICAL"
    strings:
        $bash_tcp  = "bash -i >& /dev/tcp/"        ascii
        $nc_e      = "nc -e /bin/sh"               ascii
        $nc_c      = "nc -c bash"                  ascii
        $python_rs = "python -c 'import socket"    ascii
        $php_rs    = "php -r '$sock=fsockopen"      ascii
    condition:
        any of them
}
