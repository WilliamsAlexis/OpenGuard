/*
 * OpenGuard - Reglas YARA para Mineros de Criptomonedas No Autorizados
 */

rule Generic_Cryptominer_Strings {
    meta:
        description = "Detecta protocolos de mineria Stratum y binarios de mineros conocidos"
        severity = "medium"
        malware_family = "Cryptominer"
    strings:
        $p1 = "stratum+tcp://" nocase
        $p2 = "stratum+ssl://" nocase
        $m1 = "xmrig" nocase
        $m2 = "minerd" nocase
        $m3 = "cpuminer" nocase
        $c1 = "monero" nocase
        $c2 = "cryptonight" nocase
    condition:
        ($p1 or $p2) or (2 of ($m1, $m2, $m3)) or ($c2 and ($p1 or $p2))
}

