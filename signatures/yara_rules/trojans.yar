/*
 * OpenGuard - Reglas YARA para Troyanos y Backdoors
 */

rule Generic_Backdoor_Commands {
    meta:
        description = "Detecta invocaciones tipicas de reverse shells y manipulacion de procesos"
        severity = "critical"
        malware_family = "Backdoor"
    strings:
        $cmd1 = "cmd.exe /c " nocase
        $cmd2 = "powershell -WindowStyle Hidden" nocase
        $cmd3 = "powershell -w hidden -nop" nocase
        $rat1 = "CreateRemoteThread" ascii
        $rat2 = "VirtualAllocEx" ascii
        $rat3 = "WriteProcessMemory" ascii
        $rat4 = "NtUnmapViewOfSection" ascii
    condition:
        2 of ($cmd1, $cmd2, $cmd3) or (2 of ($rat1, $rat2, $rat3, $rat4))
}

rule Suspicious_Process_Injection {
    meta:
        description = "Patron clasico de inyeccion de DLL o Process Hollowing"
        severity = "critical"
        malware_family = "ProcessInjection"
    strings:
        $p1 = "OpenProcess" ascii
        $p2 = "VirtualAllocEx" ascii
        $p3 = "WriteProcessMemory" ascii
        $p4 = "CreateRemoteThread" ascii
    condition:
        3 of them
}

