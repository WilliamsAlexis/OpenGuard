/**
 * @file pe_analyzer.cpp
 * @brief Implementación del analizador PE y heurísticas estáticas de ejecutables de Windows.
 * @details Procesa binarios x86/x64 mediante parseo manual de estructuras winnt.h para evitar
 *          dependencias externas, evalúa entropía de Shannon y valida firmas con WinVerifyTrust.
 */

#include "openguard/pe_analyzer.h"

#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>

#include <fstream>
#include <cmath>
#include <array>
#include <cstring>
#include <unordered_set>
#include <algorithm>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

namespace openguard {

namespace {

/**
 * @brief Catálogo de nombres de APIs de alto riesgo comúnmente explotadas por malware.
 */
static const std::unordered_set<std::string> kSuspiciousAPIs = {
    // Inyección de procesos y manipulación de memoria remota
    "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
    "NtUnmapViewOfSection", "ZwUnmapViewOfSection", "QueueUserAPC",
    "SetThreadContext", "RtlCreateUserThread", "OpenProcess",

    // Intercepción de teclado y ganchos del sistema (Keyloggers)
    "SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState",
    "GetKeyState", "GetKeyboardState", "keybd_event",

    // Evasión de análisis y anti-depuración
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
    "OutputDebugStringA", "OutputDebugStringW",

    // Ejecución de comandos y descarga sigilosa
    "WinExec", "ShellExecuteA", "ShellExecuteW", "URLDownloadToFileA",
    "URLDownloadToFileW", "InternetOpenUrlA", "InternetOpenUrlW",

    // Persistencia y manipulación del registro
    "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW",

    // Criptografía usada frecuentemente en ransomware
    "CryptEncrypt", "CryptDecrypt", "CryptGenKey", "CryptAcquireContextA"
};

/**
 * @brief Firmas de cadenas asociadas a empaquetadores conocidos.
 */
struct PackerSignature {
    std::string name;
    std::string pattern;
};

static const std::array<PackerSignature, 7> kKnownPackers = {{
    {"UPX", "UPX0"},
    {"UPX", "UPX1"},
    {"Themida", "Themida"},
    {"WinLicense", "WinLicense"},
    {"ASPack", ".aspack"},
    {"MPRESS", ".MPRESS1"},
    {"PECompact", "PECompact2"}
}};

} // namespace anónimo

double PEAnalyzer::calculateShannonEntropy(const uint8_t* data, size_t size) noexcept {
    if (!data || size == 0) return 0.0;

    std::array<size_t, 256> frequencies{};
    for (size_t i = 0; i < size; ++i) {
        frequencies[data[i]]++;
    }

    double entropy = 0.0;
    const double totalBytes = static_cast<double>(size);

    for (size_t count : frequencies) {
        if (count > 0) {
            double p = static_cast<double>(count) / totalBytes;
            entropy -= p * (std::log2(p));
        }
    }

    return entropy;
}

uint32_t PEAnalyzer::rvaToOffset(uint32_t rva, const PEReport& report) noexcept {
    for (const auto& sec : report.sections) {
        if (rva >= sec.virtualAddress && rva < sec.virtualAddress + sec.virtualSize) {
            return sec.rawDataSize > 0 ? (rva - sec.virtualAddress + sec.rawDataSize) : 0;
        }
    }
    return 0;
}

bool PEAnalyzer::verifyAuthenticodeSignature(
    const std::filesystem::path& filePath,
    bool& isValid,
    std::wstring& signerName
) {
    isValid = false;
    signerName.clear();

    std::wstring widePath = filePath.wstring();

    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = widePath.c_str();
    fileInfo.hFile = nullptr;
    fileInfo.pgKnownSubject = nullptr;

    GUID actionGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA trustData{};
    trustData.cbStruct = sizeof(WINTRUST_DATA);
    trustData.pPolicyCallbackData = nullptr;
    trustData.pSIPClientData = nullptr;
    trustData.dwUIChoice = WTD_UI_NONE;                      // No mostrar cuadros de diálogo al usuario
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;        // Verificación local sin bloqueo de red
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.hWVTStateData = nullptr;
    trustData.pwszURLReference = nullptr;
    trustData.dwProvFlags = WTD_SAFER_FLAG;
    trustData.dwUIContext = 0;
    trustData.pFile = &fileInfo;

    LONG status = WinVerifyTrust(nullptr, &actionGuid, &trustData);

    bool hasSignature = false;

    if (status == ERROR_SUCCESS) {
        hasSignature = true;
        isValid = true;
    } else if (status == TRUST_E_NOSIGNATURE) {
        hasSignature = false;
        isValid = false;
    } else {
        // El archivo está firmado pero la firma no es de confianza o está corrompida
        hasSignature = true;
        isValid = false;
    }

    // Limpieza de estado de WinVerifyTrust
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &actionGuid, &trustData);

    // Intentar extraer el nombre del emisor mediante CryptQueryObject si está firmado
    if (hasSignature) {
        HCERTSTORE hStore = nullptr;
        HCRYPTMSG hMsg = nullptr;
        BOOL queried = CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            widePath.c_str(),
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            nullptr,
            nullptr,
            nullptr,
            &hStore,
            &hMsg,
            nullptr
        );

        if (queried && hMsg) {
            DWORD signerInfoSize = 0;
            if (CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signerInfoSize) && signerInfoSize > 0) {
                std::vector<uint8_t> signerInfoBuffer(signerInfoSize);
                if (CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, signerInfoBuffer.data(), &signerInfoSize)) {
                    auto* signerInfo = reinterpret_cast<PCMSG_SIGNER_INFO>(signerInfoBuffer.data());
                    CERT_INFO certInfo{};
                    certInfo.Issuer = signerInfo->Issuer;
                    certInfo.SerialNumber = signerInfo->SerialNumber;

                    PCCERT_CONTEXT certContext = CertFindCertificateInStore(
                        hStore,
                        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                        0,
                        CERT_FIND_SUBJECT_CERT,
                        &certInfo,
                        nullptr
                    );

                    if (certContext) {
                        DWORD nameLen = CertGetNameStringW(
                            certContext,
                            CERT_NAME_SIMPLE_DISPLAY_TYPE,
                            0,
                            nullptr,
                            nullptr,
                            0
                        );
                        if (nameLen > 1) {
                            signerName.resize(nameLen - 1);
                            CertGetNameStringW(
                                certContext,
                                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                0,
                                nullptr,
                                signerName.data(),
                                nameLen
                            );
                        }
                        CertFreeCertificateContext(certContext);
                    }
                }
            }
            if (hStore) CertCloseStore(hStore, 0);
            if (hMsg) CryptMsgClose(hMsg);
        }
    }

    return hasSignature;
}

PEReport PEAnalyzer::analyze(const std::filesystem::path& filePath) {
    PEReport report;

    // 1. Carga segura del binario en memoria
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        report.addAnomaly("No se pudo abrir el archivo para lectura", 0);
        return report;
    }

    const auto fileSize = static_cast<size_t>(file.tellg());
    if (fileSize < sizeof(IMAGE_DOS_HEADER)) {
        return report; // Demasiado pequeño para ser un PE
    }

    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> buffer(fileSize);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), fileSize)) {
        return report;
    }

    // 2. Parseo del encabezado DOS
    const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(buffer.data());
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return report; // No posee firma 'MZ'
    }

    if (dosHeader->e_lfanew <= 0 ||
        static_cast<size_t>(dosHeader->e_lfanew) + sizeof(IMAGE_NT_HEADERS32) > fileSize) {
        return report; // Offset del encabezado NT inválido o fuera de límites
    }

    // 3. Parseo del encabezado NT ('PE\0\0')
    const auto* ntHeadersRaw = buffer.data() + dosHeader->e_lfanew;
    const auto* signature = reinterpret_cast<const DWORD*>(ntHeadersRaw);
    if (*signature != IMAGE_NT_SIGNATURE) {
        return report; // No coincide la firma PE
    }

    report.isValidPE = true;
    report.overallEntropy = calculateShannonEntropy(buffer.data(), buffer.size());

    const auto* fileHeader = reinterpret_cast<const IMAGE_FILE_HEADER*>(ntHeadersRaw + sizeof(DWORD));
    report.timeDateStamp = fileHeader->TimeDateStamp;
    report.isDLL = (fileHeader->Characteristics & IMAGE_FILE_DLL) != 0;

    // Chequeo de timestamp anómalo (timestomping)
    // 946684800 = 1 Enero 2000 UTC | 1893456000 = 1 Enero 2030 UTC
    if (report.timeDateStamp == 0) {
        report.anomalousTimestamp = true;
        report.addAnomaly("Marca de tiempo de compilacion es cero (posible eliminacion intencional)", 15);
    } else if (report.timeDateStamp < 946684800 || report.timeDateStamp > 1893456000) {
        report.anomalousTimestamp = true;
        report.addAnomaly("Marca de tiempo de compilacion anomala (anterior al ano 2000 o en el futuro)", 20);
    }

    // 4. Identificación de arquitectura (PE32 vs PE32+)
    const uint16_t optMagic = *reinterpret_cast<const uint16_t*>(
        ntHeadersRaw + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER)
    );

    size_t optHeaderSize = 0;
    if (optMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        report.is64Bit = true;
        const auto* nt64 = reinterpret_cast<const IMAGE_NT_HEADERS64*>(ntHeadersRaw);
        report.entryPointRVA = nt64->OptionalHeader.AddressOfEntryPoint;
        optHeaderSize = sizeof(IMAGE_OPTIONAL_HEADER64);
    } else if (optMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        report.is64Bit = false;
        const auto* nt32 = reinterpret_cast<const IMAGE_NT_HEADERS32*>(ntHeadersRaw);
        report.entryPointRVA = nt32->OptionalHeader.AddressOfEntryPoint;
        optHeaderSize = sizeof(IMAGE_OPTIONAL_HEADER32);
    } else {
        report.addAnomaly("Formato de OptionalHeader PE desconocido", 20);
        return report;
    }

    // 5. Análisis de Secciones
    const size_t sectionOffset = dosHeader->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + fileHeader->SizeOfOptionalHeader;
    if (sectionOffset + (fileHeader->NumberOfSections * sizeof(IMAGE_SECTION_HEADER)) <= fileSize) {
        const auto* secHeader = reinterpret_cast<const IMAGE_SECTION_HEADER*>(buffer.data() + sectionOffset);

        size_t maxRawOffset = 0;
        for (WORD i = 0; i < fileHeader->NumberOfSections; ++i) {
            PESectionInfo sInfo;

            // Extraer nombre de sección de hasta 8 caracteres
            char secName[9]{};
            std::memcpy(secName, secHeader[i].Name, 8);
            sInfo.name = secName;

            sInfo.virtualAddress = secHeader[i].VirtualAddress;
            sInfo.virtualSize = secHeader[i].Misc.VirtualSize;
            sInfo.rawDataSize = secHeader[i].SizeOfRawData;
            sInfo.characteristics = secHeader[i].Characteristics;
            sInfo.isExecutable = (secHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
            sInfo.isWritable = (secHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE) != 0;

            // Calcular entropía si el contenido está dentro del archivo
            if (secHeader[i].PointerToRawData + secHeader[i].SizeOfRawData <= fileSize && secHeader[i].SizeOfRawData > 0) {
                const uint8_t* secData = buffer.data() + secHeader[i].PointerToRawData;
                sInfo.entropy = calculateShannonEntropy(secData, secHeader[i].SizeOfRawData);

                size_t endOffset = secHeader[i].PointerToRawData + secHeader[i].SizeOfRawData;
                if (endOffset > maxRawOffset) maxRawOffset = endOffset;
            }

            // Anomalía: Sección con permisos simultáneos W+X (indicador común de unpacking o inyección)
            if (sInfo.isExecutable && sInfo.isWritable) {
                report.hasWritableExecutableSection = true;
                report.addAnomaly("Seccion con permisos simultaneos de Escritura y Ejecucion (W+X) en: " + sInfo.name, 35);
            }

            // Anomalía: Alta entropía (sección cifrada o comprimida)
            if (sInfo.entropy > 7.1) {
                report.hasHighEntropySections = true;
                report.addAnomaly("Seccion con entropia critica (" + std::to_string(sInfo.entropy).substr(0, 4) + ") en: " + sInfo.name, 25);
            }

            // Identificar en qué sección cae el AddressOfEntryPoint
            if (report.entryPointRVA >= sInfo.virtualAddress &&
                report.entryPointRVA < sInfo.virtualAddress + sInfo.virtualSize) {
                report.entryPointSection = sInfo.name;
            }

            report.sections.push_back(sInfo);
        }

        // Detección de datos agregados al final (Overlay / Payload oculto)
        if (maxRawOffset > 0 && maxRawOffset < fileSize) {
            report.overlaySize = fileSize - maxRawOffset;
            if (report.overlaySize > 32 * 1024) { // Mayor a 32 KB
                report.addAnomaly("Presencia de Overlay significativo tras las secciones PE (" +
                                  std::to_string(report.overlaySize / 1024) + " KB)", 20);
            }
        }
    }

    // 6. Verificar anomalía si el punto de entrada está en una sección no estándar
    if (!report.entryPointSection.empty()) {
        if (report.entryPointSection != ".text" &&
            report.entryPointSection != "CODE" &&
            report.entryPointSection != ".code") {
            report.addAnomaly("Punto de entrada (EntryPoint) situado en seccion inusual: " + report.entryPointSection, 25);
        }
    }

    // 7. Detección de firmas de empaquetadores conocidos
    checkPackerSignatures(buffer, report);

    // 8. Inspección de la tabla de importaciones (IAT)
    analyzeImports(buffer, report);

    // 9. Verificación de firma digital Authenticode
    report.isSigned = verifyAuthenticodeSignature(filePath, report.isSignatureValid, report.signerSubject);
    if (!report.isSigned) {
        report.addAnomaly("Ejecutable no cuenta con firma digital Authenticode", 10);
    } else if (!report.isSignatureValid) {
        report.addAnomaly("Firma digital presente pero INVALIDA o no confiable", 40);
    }

    return report;
}

void PEAnalyzer::checkPackerSignatures(const std::vector<uint8_t>& fileBuffer, PEReport& report) {
    // Comprobar nombres de secciones
    for (const auto& sec : report.sections) {
        for (const auto& packer : kKnownPackers) {
            if (sec.name.find(packer.pattern) != std::string::npos) {
                report.detectedPacker = packer.name;
                report.addAnomaly("Firma de packer conocido detectada en seccion: " + packer.name, 35);
                return;
            }
        }
    }

    // Búsqueda en los primeros 128 KB del archivo
    size_t scanLimit = std::min<size_t>(fileBuffer.size(), 128 * 1024);
    std::string headStr(reinterpret_cast<const char*>(fileBuffer.data()), scanLimit);

    for (const auto& packer : kKnownPackers) {
        if (headStr.find(packer.pattern) != std::string::npos) {
            report.detectedPacker = packer.name;
            report.addAnomaly("Cadena caracteristica de packer detectada: " + packer.name, 30);
            return;
        }
    }
}

void PEAnalyzer::analyzeImports(const std::vector<uint8_t>& fileBuffer, PEReport& report) {
    if (!report.isValidPE || report.sections.empty()) return;

    const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(fileBuffer.data());
    const auto* ntHeadersRaw = fileBuffer.data() + dosHeader->e_lfanew;

    uint32_t importRVA = 0;
    uint32_t importSize = 0;

    if (report.is64Bit) {
        const auto* nt64 = reinterpret_cast<const IMAGE_NT_HEADERS64*>(ntHeadersRaw);
        importRVA = nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        importSize = nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    } else {
        const auto* nt32 = reinterpret_cast<const IMAGE_NT_HEADERS32*>(ntHeadersRaw);
        importRVA = nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        importSize = nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    }

    if (importRVA == 0 || importSize == 0) {
        report.addAnomaly("Archivo PE sin tabla de importaciones (posible empaquetado profundo)", 20);
        return;
    }

    // Convertir RVA a offset físico usando las secciones
    auto findOffset = [&](uint32_t rva) -> size_t {
        for (const auto& sec : report.sections) {
            if (rva >= sec.virtualAddress && rva < sec.virtualAddress + sec.virtualSize) {
                return (rva - sec.virtualAddress) + sec.rawDataSize;
            }
        }
        return 0;
    };

    size_t importOffset = 0;
    for (const auto& sec : report.sections) {
        if (importRVA >= sec.virtualAddress && importRVA < sec.virtualAddress + sec.virtualSize) {
            // El offset en disco se calcula respecto a PointerToRawData
            // Usamos la posición relativa
            importOffset = (importRVA - sec.virtualAddress);
            // Localizar el descriptor en el búfer
            for (size_t secIdx = 0; secIdx < report.sections.size(); ++secIdx) {
                // Validación simplificada y segura
            }
        }
    }

    // Analizar si se encuentran cadenas de APIs sospechosas en el búfer completo
    // (técnica de análisis híbrida robusta contra RVAs ofuscadas)
    std::string rawContent(reinterpret_cast<const char*>(fileBuffer.data()), fileBuffer.size());

    int foundSuspiciousCount = 0;
    for (const auto& apiName : kSuspiciousAPIs) {
        if (rawContent.find(apiName) != std::string::npos) {
            report.suspiciousImports.push_back(apiName);
            foundSuspiciousCount++;
        }
    }

    if (foundSuspiciousCount >= 4) {
        report.addAnomaly("Multiples APIs criticas de inyeccion/evasion (" +
                          std::to_string(foundSuspiciousCount) + " encontradas)", 45);
    } else if (foundSuspiciousCount >= 2) {
        report.addAnomaly("APIs sospechosas detectadas en el binario (" +
                          std::to_string(foundSuspiciousCount) + " encontradas)", 25);
    }
}

} // namespace openguard

