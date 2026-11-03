/*
 * OpenGuard - Reglas YARA para Ransomware y Destruccion de Copias
 */

rule Generic_Ransomware_Note {
    meta:
        description = "Detecta frases universales en notas de rescate dejadas por ransomware"
        severity = "critical"
        malware_family = "Ransomware"
    strings:
        $note1 = "YOUR FILES HAVE BEEN ENCRYPTED" nocase
        $note2 = "ALL YOUR FILES ARE ENCRYPTED" nocase
        $note3 = "To decrypt your files" nocase
        $note4 = "Send Bitcoin" nocase
        $note5 = "decrypt your data" nocase
        $note6 = "HOW TO RECOVER" nocase
        $note7 = ".onion" nocase
        $note8 = "vssadmin.exe delete shadows" nocase
    condition:
        2 of them
}

rule Ransomware_API_Combination {
    meta:
        description = "Combinacion de APIs para enumeracion de archivos, cifrado y borrado de instantaneas"
        severity = "high"
        malware_family = "Ransomware-API"
    strings:
        $enc1 = "CryptEncrypt" ascii
        $enc2 = "CryptGenKey" ascii
        $enum1 = "FindFirstFileW" ascii
        $enum2 = "FindNextFileW" ascii
        $del = "DeleteFileW" ascii
        $vss = "vssadmin" nocase
    condition:
        ($enc1 or $enc2) and ($enum1 or $enum2) and ($del or $vss)
}

