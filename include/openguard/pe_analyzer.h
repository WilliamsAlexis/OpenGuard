/**
 * @file pe_analyzer.h
 * @brief Analizador estático y heurístico de binarios PE (Portable Executable) para Windows.
 * @details Realiza el parseo seguro de encabezados PE (PE32/PE32+) utilizando las estructuras
 *          de winnt.h, cálculo de entropía de Shannon por sección, detección de packers,
 *          análisis de tablas de importación (IAT) y verificación de firmas Authenticode con WinVerifyTrust.
 */

#pragma once

#include "openguard/types.h"

#include <string>
#include <vector>
#include <filesystem>
#include <cstdint>
#include <optional>

namespace openguard {

/**
 * @struct PESectionInfo
 * @brief Metadatos y características de una sección individual del archivo PE.
 */
struct PESectionInfo {
    std::string name;               ///< Nombre de la sección (ej: ".text", ".data", ".rsrc").
    uint32_t virtualAddress{0};     ///< Dirección virtual relativa (RVA).
    uint32_t virtualSize{0};        ///< Tamaño de la sección en memoria.
    uint32_t rawDataSize{0};        ///< Tamaño de los datos en disco.
    uint32_t rawDataPointer{0};     ///< Offset físico de los datos en el archivo (PointerToRawData).
    uint32_t characteristics{0};    ///< Flags de características (IMAGE_SCN_MEM_EXECUTE, etc.).
    double entropy{0.0};            ///< Entropía de Shannon calculada (0.0 a 8.0).
    bool isExecutable{false};       ///< Indica si la sección tiene permisos de ejecución.
    bool isWritable{false};         ///< Indica si la sección tiene permisos de escritura.
};

/**
 * @struct PEReport
 * @brief Informe exhaustivo de la inspección estática del ejecutable PE.
 */
struct PEReport {
    bool isValidPE{false};                  ///< Indica si el archivo posee una estructura PE válida.
    bool is64Bit{false};                    ///< true si es PE32+ (x64); false si es PE32 (x86).
    bool isDLL{false};                      ///< true si es una biblioteca dinámica DLL.
    uint32_t entryPointRVA{0};              ///< Dirección RVA del punto de entrada (AddressOfEntryPoint).
    std::string entryPointSection;          ///< Nombre de la sección donde reside el punto de entrada.
    uint32_t timeDateStamp{0};              ///< Marca de tiempo de compilación registrada en el encabezado.
    bool anomalousTimestamp{false};         ///< true si el timestamp es futuro, cero o anterior al año 2000.
    
    // Entropía y empaquetamiento
    double overallEntropy{0.0};             ///< Entropía promedio de todo el archivo.
    bool hasHighEntropySections{false};     ///< true si alguna sección supera el umbral crítico (>7.0).
    std::string detectedPacker;             ///< Nombre del packer detectado si coincide con firmas conocidas.
    
    // Secciones y características anómalas
    std::vector<PESectionInfo> sections;    ///< Desglose de todas las secciones encontradas.
    bool hasWritableExecutableSection{false}; ///< true si existe sección con W+X (indicador de inyección/unpacking).
    size_t overlaySize{0};                  ///< Tamaño en bytes de datos añadidos al final del PE (Overlay).
    
    // Importaciones
    std::vector<std::string> importedDLLs;  ///< Lista de DLLs importadas.
    std::vector<std::string> suspiciousImports; ///< Funciones sospechosas encontradas (ej: VirtualAllocEx).
    
    // Firma Digital
    bool isSigned{false};                   ///< true si el archivo contiene certificado Authenticode.
    bool isSignatureValid{false};           ///< true si la firma es criptográficamente válida y de confianza.
    std::wstring signerSubject;             ///< Nombre de la entidad emisora/firmante si está disponible.

    // Evaluación de Riesgo Heurístico
    int heuristicScore{0};                  ///< Puntos de riesgo acumulados por anomalías PE (0 a 100).
    std::vector<std::string> anomalyReasons;///< Explicación detallada de cada anomalía detectada.

    /**
     * @brief Registra una anomalía heurística y suma puntos de riesgo.
     * @param reason Descripción técnica de la anomalía.
     * @param score Puntos a sumar (limitado a 100).
     */
    void addAnomaly(const std::string& reason, int score) {
        anomalyReasons.push_back(reason);
        heuristicScore = std::min(100, heuristicScore + score);
    }
};

/**
 * @class PEAnalyzer
 * @brief Motor de análisis estático profundo de ejecutables PE para arquitecturas x86 y x64.
 */
class PEAnalyzer {
public:
    /**
     * @brief Constructor del analizador PE.
     */
    PEAnalyzer() = default;

    /**
     * @brief Destructor del analizador.
     */
    ~PEAnalyzer() = default;

    /**
     * @brief Analiza un ejecutable PE en disco inspeccionando encabezados, IAT y firmas digitales.
     * @param filePath Ruta del archivo a examinar.
     * @return PEReport con el diagnóstico estático y puntuación de riesgo.
     */
    [[nodiscard]] PEReport analyze(const std::filesystem::path& filePath);

    /**
     * @brief Calcula la entropía de Shannon matemática de un búfer de bytes.
     * @details Mide la aleatoriedad de los datos entre 0.0 (constante) y 8.0 (cifrado/empaquetado).
     * @param data Puntero al búfer de bytes.
     * @param size Longitud del búfer en bytes.
     * @return Valor de entropía en punto flotante.
     */
    [[nodiscard]] static double calculateShannonEntropy(const uint8_t* data, size_t size) noexcept;

    /**
     * @brief Verifica la firma digital Authenticode de un archivo mediante WinVerifyTrust.
     * @param filePath Ruta del archivo en Windows.
     * @param[out] isValid Indica si la firma es válida y de confianza ante la CA de Windows.
     * @param[out] signerName Nombre del firmante si se logra extraer del certificado.
     * @return true si el archivo cuenta con firma digital (incluso si no es válida); false si no está firmado.
     */
    [[nodiscard]] static bool verifyAuthenticodeSignature(
        const std::filesystem::path& filePath,
        bool& isValid,
        std::wstring& signerName
    );

private:
    /**
     * @brief Inspecciona las secciones buscando secciones con alta entropía o permisos W+X.
     */
    void analyzeSections(const std::vector<uint8_t>& fileBuffer, PEReport& report);

    /**
     * @brief Parsea la tabla de importación (IAT) y detecta APIs típicas de malware.
     */
    void analyzeImports(const std::vector<uint8_t>& fileBuffer, PEReport& report);

    /**
     * @brief Detecta firmas de empaquetadores conocidos en los encabezados o secciones.
     */
    void checkPackerSignatures(const std::vector<uint8_t>& fileBuffer, PEReport& report);

    /**
     * @brief Convierte una RVA (Relative Virtual Address) en un offset físico en el archivo.
     */
    static uint32_t rvaToOffset(uint32_t rva, const PEReport& report) noexcept;
};

} // namespace openguard

