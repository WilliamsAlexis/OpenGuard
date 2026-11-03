/**
 * @file pe_analyzer.cpp
 * @brief Implementación del analizador PE y heurísticas estáticas de ejecutables de Windows.
 * @details Procesa binarios x86/x64 mediante parseo manual de estructuras winnt.h para evitar
 *          dependencias externas, evalúa entropía de Shannon y valida firmas con WinVerifyTrust
 *          (firma embebida y firma por catálogo del sistema).
 */

#include "openguard/pe_analyzer.h"

#include <windows.h>
#include <bcrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <mscat.h>

#include <fstream>
#include <cmath>
#include <array>
#include <cstring>
#include <ctime>
#include <initializer_list>
#include <string_view>
#include <unordered_set>
#include <algorithm>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

namespace openguard {

namespace {

/**
 * @brief Catálogo de nombres de APIs de alto riesgo comúnmente explotadas por malware.
 * @details Una API aislada NO puntúa: solo las combinaciones características (ver analyzeImports),
 *          para evitar falsos positivos sobre software legítimo.
 */
const std::unordered_set<std::string> kSuspiciousAPIs = {
    // Inyección de procesos y manipulación de memoria remota
    "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
    "NtUnmapViewOfSection", "ZwUnmapViewOfSection", "QueueUserAPC",
    "SetThreadContext", "RtlCreateUserThread", "OpenProcess",

    // Intercepción de teclado y ganchos del sistema (Keyloggers)
    "SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState",
    "GetKeyboardState", "keybd_event",

    // Evasión de análisis y anti-depuración
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",

    // Ejecución de comandos y descarga sigilosa
    "WinExec", "ShellExecuteA", "ShellExecuteW", "URLDownloadToFileA",
    "URLDownloadToFileW", "InternetOpenUrlA", "InternetOpenUrlW",

    // Criptografía clásica usada frecuentemente en ransomware
    "CryptEncrypt", "CryptGenKey"
};

/**
 * @brief Firmas de cadenas asociadas a empaquetadores conocidos.
 */
struct PackerSignature {
    const char* name;
    const char* pattern;
};

const std::array<PackerSignature, 7> kKnownPackers = {{
    {"UPX", "UPX0"},
    {"UPX", "UPX1"},
    {"Themida", "Themida"},
    {"WinLicense", "WinLicense"},
    {"ASPack", ".aspack"},
    {"MPRESS", ".MPRESS1"},
    {"PECompact", "PECompact2"}
}};

/**
 * @brief Lee una cadena C terminada en NUL desde un búfer con control de límites.
 */
std::string readCString(const std::vector<uint8_t>& buf, size_t offset, size_t maxLen = 256) {
    std::string out;
    if (offset >= buf.size()) return out;
    const size_t limit = std::min(buf.size(), offset + maxLen);
    for (size_t i = offset; i < limit; ++i) {
        if (buf[i] == 0) return out;
        out.push_back(static_cast<char>(buf[i]));
    }
    return {}; // Sin terminador dentro del límite: dato corrupto
}

/**
 * @brief Verifica una firma Authenticode por catálogo (la usan los binarios de Windows).
 * @param path Ruta del archivo.
 * @return true si el archivo está listado en un catálogo del sistema con firma válida.
 */
bool verifyCatalogSignature(const std::wstring& path) {
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    bool ok = false;
    HCATADMIN hAdmin = nullptr;
    if (CryptCATAdminAcquireContext2(&hAdmin, nullptr, BCRYPT_SHA256_ALGORITHM, nullptr, 0)) {
        DWORD hashLen = 0;
        CryptCATAdminCalcHashFromFileHandle2(hAdmin, hFile, &hashLen, nullptr, 0);
        if (hashLen > 0) {
            std::vector<BYTE> hash(hashLen);
            if (CryptCATAdminCalcHashFromFileHandle2(hAdmin, hFile, &hashLen, hash.data(), 0)) {
                HCATINFO hCat = CryptCATAdminEnumCatalogFromHash(hAdmin, hash.data(), hashLen, 0, nullptr);
                if (hCat) {
                    CATALOG_INFO catInfo{};
                    catInfo.cbStruct = sizeof(catInfo);
                    if (CryptCATCatalogInfoFromContext(hCat, &catInfo, 0)) {
                        static const wchar_t kHex[] = L"0123456789ABCDEF";
                        std::wstring tag;
                        for (DWORD i = 0; i < hashLen; ++i) {
                            tag.push_back(kHex[hash[i] >> 4]);
                            tag.push_back(kHex[hash[i] & 0x0F]);
                        }

                        WINTRUST_CATALOG_INFO wci{};
                        wci.cbStruct = sizeof(wci);
                        wci.pcwszCatalogFilePath = catInfo.wszCatalogFile;
                        wci.pcwszMemberTag = tag.c_str();
                        wci.pcwszMemberFilePath = path.c_str();
                        wci.hMemberFile = hFile;
                        wci.pbCalculatedFileHash = hash.data();
                        wci.cbCalculatedFileHash = hashLen;
                        wci.hCatAdmin = hAdmin;

                        WINTRUST_DATA wtd{};
                        wtd.cbStruct = sizeof(wtd);
                        wtd.dwUIChoice = WTD_UI_NONE;
                        wtd.fdwRevocationChecks = WTD_REVOKE_NONE;
                        wtd.dwUnionChoice = WTD_CHOICE_CATALOG;
                        wtd.dwStateAction = WTD_STATEACTION_VERIFY;
                        wtd.pCatalog = &wci;

                        GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
                        ok = (WinVerifyTrust(nullptr, &action, &wtd) == ERROR_SUCCESS);

                        wtd.dwStateAction = WTD_STATEACTION_CLOSE;
                        WinVerifyTrust(nullptr, &action, &wtd);
                    }
                    CryptCATAdminReleaseCatalogContext(hAdmin, hCat, 0);
                }
            }
        }
        CryptCATAdminReleaseContext(hAdmin, 0);
    }

    CloseHandle(hFile);
    return ok;
}

} // namespace

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
        const uint64_t span = std::max<uint32_t>(sec.virtualSize, sec.rawDataSize);
        if (rva >= sec.virtualAddress && rva < static_cast<uint64_t>(sec.virtualAddress) + span) {
            const uint32_t delta = rva - sec.virtualAddress;
            if (delta >= sec.rawDataSize) return 0; // Región sin respaldo en disco (BSS)
            return sec.rawDataPointer + delta;
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
    } else if (static_cast<DWORD>(status) == static_cast<DWORD>(TRUST_E_NOSIGNATURE) ||
               static_cast<DWORD>(status) == static_cast<DWORD>(TRUST_E_PROVIDER_UNKNOWN) ||
               static_cast<DWORD>(status) == static_cast<DWORD>(TRUST_E_SUBJECT_FORM_UNKNOWN)) {
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

    // Sin firma embebida: los componentes de Windows se firman mediante catálogos del sistema.
    if (!hasSignature) {
        if (verifyCatalogSignature(widePath)) {
            signerName = L"Catalogo de seguridad de Windows";
            isValid = true;
            return true;
        }
        return false;
    }

    // Intentar extraer el nombre del emisor mediante CryptQueryObject
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
                        certContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, nullptr, 0);
                    if (nameLen > 1) {
                        signerName.resize(nameLen - 1);
                        CertGetNameStringW(
                            certContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr,
                            signerName.data(), nameLen);
                    }
                    CertFreeCertificateContext(certContext);
                }
            }
        }
    }
    if (hStore) CertCloseStore(hStore, 0);
    if (hMsg) CryptMsgClose(hMsg);

    return hasSignature;
}

PEReport PEAnalyzer::analyze(const std::filesystem::path& filePath) {
    PEReport report;

    // 1. Carga segura del binario en memoria
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        return report;
    }

    const auto endPos = file.tellg();
    if (endPos < 0) return report;
    const auto fileSize = static_cast<size_t>(endPos);
    if (fileSize < sizeof(IMAGE_DOS_HEADER)) {
        return report; // Demasiado pequeño para ser un PE
    }

    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> buffer(fileSize);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(fileSize))) {
        return report;
    }
    file.close();

    return analyzeBuffer(buffer, &filePath);
}

PEReport PEAnalyzer::analyzeBuffer(const std::vector<uint8_t>& buffer, const std::filesystem::path* signaturePath) {
    PEReport report;
    const size_t fileSize = buffer.size();
    if (fileSize < sizeof(IMAGE_DOS_HEADER)) {
        return report; // Demasiado pequeño para ser un PE
    }

    // 2. Parseo del encabezado DOS
    IMAGE_DOS_HEADER dosHeader{};
    std::memcpy(&dosHeader, buffer.data(), sizeof(dosHeader));
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        return report; // No posee firma 'MZ'
    }

    if (dosHeader.e_lfanew <= 0 ||
        static_cast<size_t>(dosHeader.e_lfanew) + sizeof(IMAGE_NT_HEADERS32) > fileSize) {
        return report; // Offset del encabezado NT inválido o fuera de límites
    }
    const size_t ntOffset = static_cast<size_t>(dosHeader.e_lfanew);

    // 3. Parseo del encabezado NT ('PE\0\0')
    DWORD peSignature = 0;
    std::memcpy(&peSignature, buffer.data() + ntOffset, sizeof(peSignature));
    if (peSignature != IMAGE_NT_SIGNATURE) {
        return report; // No coincide la firma PE
    }

    report.isValidPE = true;
    report.overallEntropy = calculateShannonEntropy(buffer.data(), buffer.size());

    IMAGE_FILE_HEADER fileHeader{};
    std::memcpy(&fileHeader, buffer.data() + ntOffset + sizeof(DWORD), sizeof(fileHeader));
    report.timeDateStamp = fileHeader.TimeDateStamp;
    report.isDLL = (fileHeader.Characteristics & IMAGE_FILE_DLL) != 0;

    // Chequeo de timestamp anómalo. Las compilaciones reproducibles (/Brepro, Go) usan valores
    // arbitrarios o cero, por lo que el peso es bajo: solo es un indicio débil.
    const auto nowSecs = static_cast<uint32_t>(std::time(nullptr));
    if (report.timeDateStamp != 0 &&
        (report.timeDateStamp < 946684800u || report.timeDateStamp > nowSecs + 86400u)) {
        report.anomalousTimestamp = true;
        report.addAnomaly("Marca de tiempo de compilacion anomala (anterior al ano 2000 o en el futuro)", 5);
    }

    // 4. Identificación de arquitectura (PE32 vs PE32+)
    uint16_t optMagic = 0;
    std::memcpy(&optMagic, buffer.data() + ntOffset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER), sizeof(optMagic));

    if (optMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        report.is64Bit = true;
        if (ntOffset + sizeof(IMAGE_NT_HEADERS64) > fileSize) return report;
        IMAGE_NT_HEADERS64 nt64{};
        std::memcpy(&nt64, buffer.data() + ntOffset, sizeof(nt64));
        report.entryPointRVA = nt64.OptionalHeader.AddressOfEntryPoint;
    } else if (optMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        report.is64Bit = false;
        IMAGE_NT_HEADERS32 nt32{};
        std::memcpy(&nt32, buffer.data() + ntOffset, sizeof(nt32));
        report.entryPointRVA = nt32.OptionalHeader.AddressOfEntryPoint;
    } else {
        report.addAnomaly("Formato de OptionalHeader PE desconocido", 20);
        return report;
    }

    // 5. Análisis de Secciones
    const size_t sectionOffset = ntOffset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + fileHeader.SizeOfOptionalHeader;
    const size_t sectionTableSize = static_cast<size_t>(fileHeader.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER);
    if (sectionOffset + sectionTableSize <= fileSize) {
        size_t maxRawOffset = 0;
        for (WORD i = 0; i < fileHeader.NumberOfSections; ++i) {
            IMAGE_SECTION_HEADER sh{};
            std::memcpy(&sh, buffer.data() + sectionOffset + i * sizeof(IMAGE_SECTION_HEADER), sizeof(sh));

            PESectionInfo sInfo;

            // Extraer nombre de sección de hasta 8 caracteres
            char secName[9]{};
            std::memcpy(secName, sh.Name, 8);
            sInfo.name = secName;

            sInfo.virtualAddress = sh.VirtualAddress;
            sInfo.virtualSize = sh.Misc.VirtualSize;
            sInfo.rawDataSize = sh.SizeOfRawData;
            sInfo.rawDataPointer = sh.PointerToRawData;
            sInfo.characteristics = sh.Characteristics;
            sInfo.isExecutable = (sh.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
            sInfo.isWritable = (sh.Characteristics & IMAGE_SCN_MEM_WRITE) != 0;

            // Calcular entropía si el contenido está dentro del archivo
            const uint64_t rawEnd = static_cast<uint64_t>(sh.PointerToRawData) + sh.SizeOfRawData;
            if (sh.SizeOfRawData > 0 && rawEnd <= fileSize) {
                sInfo.entropy = calculateShannonEntropy(buffer.data() + sh.PointerToRawData, sh.SizeOfRawData);
                if (rawEnd > maxRawOffset) maxRawOffset = static_cast<size_t>(rawEnd);
            }

            // Anomalía: Sección con permisos simultáneos W+X (indicador común de unpacking o inyección)
            if (sInfo.isExecutable && sInfo.isWritable) {
                report.hasWritableExecutableSection = true;
                report.addAnomaly("Seccion con permisos simultaneos de Escritura y Ejecucion (W+X) en: " + sInfo.name, 30);
            }

            // Anomalía: Alta entropía en secciones ejecutables (código cifrado o comprimido).
            // Los recursos (.rsrc) y datos suelen estar comprimidos legítimamente.
            if (sInfo.entropy > 7.1 && sInfo.isExecutable) {
                report.hasHighEntropySections = true;
                report.addAnomaly("Seccion ejecutable con entropia critica (" +
                                  std::to_string(sInfo.entropy).substr(0, 4) + ") en: " + sInfo.name, 30);
            } else if (sInfo.entropy > 7.1) {
                report.hasHighEntropySections = true;
            }

            // Identificar en qué sección cae el AddressOfEntryPoint
            const uint64_t span = std::max<uint32_t>(sInfo.virtualSize, sInfo.rawDataSize);
            if (report.entryPointRVA != 0 &&
                report.entryPointRVA >= sInfo.virtualAddress &&
                report.entryPointRVA < static_cast<uint64_t>(sInfo.virtualAddress) + span) {
                report.entryPointSection = sInfo.name;
            }

            report.sections.push_back(sInfo);
        }

        // Detección de datos agregados al final (Overlay / Payload oculto).
        // Los instaladores y ejecutables firmados llevan overlay legítimo, por eso el peso es bajo.
        if (maxRawOffset > 0 && maxRawOffset < fileSize) {
            report.overlaySize = fileSize - maxRawOffset;
            if (report.overlaySize > 32 * 1024) {
                report.addAnomaly("Presencia de Overlay significativo tras las secciones PE (" +
                                  std::to_string(report.overlaySize / 1024) + " KB)", 5);
            }
        }
    }

    // 6. Verificar anomalía si el punto de entrada está en una sección no estándar
    if (!report.entryPointSection.empty() && !report.isDLL) {
        static const std::unordered_set<std::string> kStandardCodeSections = {
            ".text", "CODE", ".code", ".textbss", "INIT", ".itext"
        };
        if (kStandardCodeSections.find(report.entryPointSection) == kStandardCodeSections.end()) {
            report.addAnomaly("Punto de entrada (EntryPoint) situado en seccion inusual: " + report.entryPointSection, 20);
        }
    }

    // 7. Detección de firmas de empaquetadores conocidos
    checkPackerSignatures(buffer, report);

    // 8. Inspección de la tabla de importaciones (IAT)
    analyzeImports(buffer, report);

    // 9. Verificación de firma digital Authenticode (necesita acceso al archivo y a servicios del
    //    sistema: se omite cuando el análisis se hace sobre memoria, p. ej. en el proceso aislado)
    if (signaturePath) {
        bool valid = false;
        std::wstring signer;
        const bool hasSignature = verifyAuthenticodeSignature(*signaturePath, valid, signer);
        applySignatureResult(report, hasSignature, valid, signer);
    }

    return report;
}

void PEAnalyzer::applySignatureResult(PEReport& report, bool isSigned, bool isValid, const std::wstring& signer) {
    report.isSigned = isSigned;
    report.isSignatureValid = isValid;
    report.signerSubject = signer;
    if (!report.isSigned) {
        report.addAnomaly("Ejecutable no cuenta con firma digital Authenticode", 10);
    } else if (!report.isSignatureValid) {
        report.addAnomaly("Firma digital presente pero INVALIDA o no confiable", 40);
    } else if (report.heuristicScore > 0) {
        // Una firma válida y confiable reduce sustancialmente la sospecha de las anomalías estructurales
        report.heuristicScore = report.heuristicScore / 2;
    }
}

void PEAnalyzer::checkPackerSignatures(const std::vector<uint8_t>& fileBuffer, PEReport& report) {
    // Comprobar nombres de secciones
    for (const auto& sec : report.sections) {
        for (const auto& packer : kKnownPackers) {
            if (sec.name.find(packer.pattern) != std::string::npos) {
                report.detectedPacker = packer.name;
                report.addAnomaly(std::string("Firma de packer conocido detectada en seccion: ") + packer.name, 35);
                return;
            }
        }
    }

    // Búsqueda en los primeros 4 KB (encabezados y tabla de secciones), donde residen los marcadores
    const size_t scanLimit = std::min<size_t>(fileBuffer.size(), 4096);
    const std::string_view head(reinterpret_cast<const char*>(fileBuffer.data()), scanLimit);

    for (const auto& packer : kKnownPackers) {
        if (head.find(packer.pattern) != std::string_view::npos) {
            report.detectedPacker = packer.name;
            report.addAnomaly(std::string("Cadena caracteristica de packer detectada: ") + packer.name, 30);
            return;
        }
    }
}

void PEAnalyzer::analyzeImports(const std::vector<uint8_t>& fileBuffer, PEReport& report) {
    if (!report.isValidPE || report.sections.empty()) return;

    IMAGE_DOS_HEADER dosHeader{};
    std::memcpy(&dosHeader, fileBuffer.data(), sizeof(dosHeader));
    const size_t ntOffset = static_cast<size_t>(dosHeader.e_lfanew);

    uint32_t importRVA = 0;
    uint32_t importSize = 0;

    if (report.is64Bit) {
        IMAGE_NT_HEADERS64 nt64{};
        std::memcpy(&nt64, fileBuffer.data() + ntOffset, sizeof(nt64));
        importRVA = nt64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        importSize = nt64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    } else {
        IMAGE_NT_HEADERS32 nt32{};
        std::memcpy(&nt32, fileBuffer.data() + ntOffset, sizeof(nt32));
        importRVA = nt32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        importSize = nt32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    }

    if (importRVA == 0 || importSize == 0) {
        // Las DLL de solo recursos carecen de imports de forma legítima
        if (!report.isDLL) {
            report.addAnomaly("Ejecutable sin tabla de importaciones (posible empaquetado profundo)", 20);
        }
        return;
    }

    const size_t descOffset = rvaToOffset(importRVA, report);
    if (descOffset == 0 || descOffset + sizeof(IMAGE_IMPORT_DESCRIPTOR) > fileBuffer.size()) {
        report.addAnomaly("Tabla de importaciones corrupta o fuera de los limites del archivo", 15);
        return;
    }

    constexpr size_t kMaxDescriptors = 1024;   // Límite defensivo ante tablas malformadas
    constexpr size_t kMaxThunksPerDll = 8192;
    const size_t thunkSize = report.is64Bit ? sizeof(uint64_t) : sizeof(uint32_t);

    std::unordered_set<std::string> found;

    for (size_t i = 0; i < kMaxDescriptors; ++i) {
        const size_t off = descOffset + i * sizeof(IMAGE_IMPORT_DESCRIPTOR);
        if (off + sizeof(IMAGE_IMPORT_DESCRIPTOR) > fileBuffer.size()) break;

        IMAGE_IMPORT_DESCRIPTOR desc{};
        std::memcpy(&desc, fileBuffer.data() + off, sizeof(desc));
        if (desc.Name == 0 && desc.FirstThunk == 0) break; // Descriptor nulo: fin de la tabla

        std::string dllName = readCString(fileBuffer, rvaToOffset(desc.Name, report));
        if (!dllName.empty()) report.importedDLLs.push_back(dllName);

        const uint32_t thunkRva = desc.OriginalFirstThunk ? desc.OriginalFirstThunk : desc.FirstThunk;
        const size_t thunkOffset = rvaToOffset(thunkRva, report);
        if (thunkOffset == 0) continue;

        for (size_t j = 0; j < kMaxThunksPerDll; ++j) {
            const size_t to = thunkOffset + j * thunkSize;
            if (to + thunkSize > fileBuffer.size()) break;

            uint64_t value = 0;
            std::memcpy(&value, fileBuffer.data() + to, thunkSize);
            if (value == 0) break;

            const bool byOrdinal = report.is64Bit ? ((value >> 63) & 1) != 0 : ((value >> 31) & 1) != 0;
            if (byOrdinal) continue;

            const size_t nameOffset = rvaToOffset(static_cast<uint32_t>(value & 0x7FFFFFFFu), report);
            if (nameOffset == 0) continue;

            // IMAGE_IMPORT_BY_NAME: 2 bytes de 'Hint' seguidos del nombre
            std::string fn = readCString(fileBuffer, nameOffset + 2);
            if (kSuspiciousAPIs.count(fn)) found.insert(fn);
        }
    }

    report.suspiciousImports.assign(found.begin(), found.end());
    std::sort(report.suspiciousImports.begin(), report.suspiciousImports.end());

    auto has = [&](const char* n) { return found.count(n) > 0; };
    auto hasAny = [&](std::initializer_list<const char*> names) {
        return std::any_of(names.begin(), names.end(), [&](const char* n) { return has(n); });
    };

    // Solo las combinaciones características puntúan; una API aislada es habitual en software legítimo.
    if (has("VirtualAllocEx") && has("WriteProcessMemory") &&
        hasAny({"CreateRemoteThread", "SetThreadContext", "QueueUserAPC", "RtlCreateUserThread"})) {
        report.addAnomaly("Combinacion de APIs de inyeccion de codigo en procesos remotos "
                          "(VirtualAllocEx + WriteProcessMemory + hilo remoto)", 45);
    }
    if (hasAny({"NtUnmapViewOfSection", "ZwUnmapViewOfSection"}) &&
        has("WriteProcessMemory") && has("SetThreadContext")) {
        report.addAnomaly("Patron de Process Hollowing (UnmapViewOfSection + WriteProcessMemory + SetThreadContext)", 50);
    }
    if (hasAny({"SetWindowsHookExA", "SetWindowsHookExW"}) &&
        hasAny({"GetAsyncKeyState", "GetKeyboardState"})) {
        report.addAnomaly("Combinacion tipica de keylogger (SetWindowsHookEx + lectura de estado de teclado)", 30);
    }
    if (hasAny({"URLDownloadToFileA", "URLDownloadToFileW"}) &&
        hasAny({"WinExec", "ShellExecuteA", "ShellExecuteW"})) {
        report.addAnomaly("Patron de descargador (URLDownloadToFile + ejecucion de lo descargado)", 35);
    }
    if (has("IsDebuggerPresent") && has("CheckRemoteDebuggerPresent") && has("NtQueryInformationProcess")) {
        report.addAnomaly("Multiples tecnicas anti-depuracion combinadas", 15);
    }
}

} // namespace openguard
