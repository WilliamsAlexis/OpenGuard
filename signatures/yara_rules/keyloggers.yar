/*
 * OpenGuard - Reglas YARA para Keyloggers e Intercepcion de Teclado
 */

rule Generic_Keylogger_APIs {
    meta:
        description = "Identifica el uso reiterado de APIs de Windows para captura de pulsaciones"
        severity = "high"
        malware_family = "Keylogger"
    strings:
        $k1 = "GetAsyncKeyState" ascii
        $k2 = "SetWindowsHookEx" ascii
        $k3 = "GetKeyboardState" ascii
        $k4 = "keybd_event" ascii
        $log1 = "keylog" nocase
        $log2 = "keystroke" nocase
    condition:
        (2 of ($k1, $k2, $k3, $k4)) or (1 of ($k1, $k2, $k3, $k4) and 1 of ($log1, $log2))
}

