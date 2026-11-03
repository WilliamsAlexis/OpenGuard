/*
 * OpenGuard - Reglas YARA para Webshells
 */

rule Generic_PHP_Webshell {
    meta:
        description = "Detecta funciones de ejecucion de comandos invocadas desde parametros web"
        severity = "critical"
        malware_family = "Webshell-PHP"
    strings:
        $php = "<?php" nocase
        $eval = "eval(" nocase
        $exec1 = "shell_exec(" nocase
        $exec2 = "system(" nocase
        $exec3 = "passthru(" nocase
        $b64 = "base64_decode" nocase
        $req1 = "$_POST" nocase
        $req2 = "$_GET" nocase
        $req3 = "$_REQUEST" nocase
    condition:
        $php and ($b64 or $eval or $exec1 or $exec2 or $exec3) and ($req1 or $req2 or $req3)
}

