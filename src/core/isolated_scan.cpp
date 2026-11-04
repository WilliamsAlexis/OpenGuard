/**
 * @file isolated_scan.cpp
 * @brief Implementación del análisis aislado (token restringido + integridad baja + Job Object).
 */

#include "openguard/isolated_scan.h"
#include "openguard/content_analysis.h"
#include "openguard/heuristics.h"
#include "openguard/paths.h"
#include "openguard/pe_analyzer.h"
#include "openguard/scanner.h"

#include <windows.h>
#include <sddl.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <vector>

namespace openguard {

namespace {

constexpr size_t kMaxOutputBytes = 1024 * 1024;

/// RAII para HANDLE de Windows.
class Handle {
public:
    Handle() = default;
    explicit Handle(HANDLE h) : m_h(h) {}
    ~Handle() { reset(); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    Handle(Handle&& o) noexcept : m_h(o.release()) {}
    Handle& operator=(Handle&& o) noexcept { if (this != &o) { reset(); m_h = o.release(); } return *this; }

    [[nodiscard]] HANDLE get() const { return m_h; }
    [[nodiscard]] bool valid() const { return m_h && m_h != INVALID_HANDLE_VALUE; }
    HANDLE release() { HANDLE h = m_h; m_h = nullptr; return h; }
    void reset(HANDLE h = nullptr) { if (valid()) CloseHandle(m_h); m_h = h; }

private:
    HANDLE m_h{nullptr};
};

enum class RunStatus { Ok, StartFailed, Timeout, Crashed, BadOutput };

/// Crea un token primario restringido: sin privilegios, Administradores en solo-denegar e integridad baja.
Handle makeSandboxToken() {
    HANDLE self = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT, &self)) {
        return Handle();
    }
    Handle selfH(self);

    BYTE adminSid[SECURITY_MAX_SID_SIZE]{};
    DWORD sidSize = sizeof(adminSid);
    if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, adminSid, &sidSize)) return Handle();
    SID_AND_ATTRIBUTES disable[1];
    disable[0].Sid = adminSid;
    disable[0].Attributes = 0;

    HANDLE restricted = nullptr;
    if (!CreateRestrictedToken(selfH.get(), DISABLE_MAX_PRIVILEGE, 1, disable, 0, nullptr, 0, nullptr, &restricted)) {
        return Handle();
    }
    Handle token(restricted);

    PSID lowSid = nullptr;
    if (!ConvertStringSidToSidW(L"S-1-16-4096", &lowSid)) return Handle(); // SECURITY_MANDATORY_LOW_RID
    TOKEN_MANDATORY_LABEL tml{};
    tml.Label.Attributes = SE_GROUP_INTEGRITY;
    tml.Label.Sid = lowSid;
    const BOOL ok = SetTokenInformation(token.get(), TokenIntegrityLevel, &tml,
                                        static_cast<DWORD>(sizeof(tml)) + GetLengthSid(lowSid));
    LocalFree(lowSid);
    if (!ok) return Handle();
    return token;
}

Handle makeJob(size_t memoryLimit) {
    Handle job(CreateJobObjectW(nullptr, nullptr));
    if (!job.valid()) return Handle();

    JOBOBJECT_EXTENDED_LIMIT_INFORMATION li{};
    li.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
                                          JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
    li.BasicLimitInformation.ActiveProcessLimit = 1;
    li.ProcessMemoryLimit = memoryLimit;
    if (!SetInformationJobObject(job.get(), JobObjectExtendedLimitInformation, &li, sizeof(li))) return Handle();

    JOBOBJECT_BASIC_UI_RESTRICTIONS ui{};
    ui.UIRestrictionsClass = JOB_OBJECT_UILIMIT_ALL;
    SetInformationJobObject(job.get(), JobObjectBasicUIRestrictions, &ui, sizeof(ui));
    return job;
}

std::string sanitizeExtension(const std::filesystem::path& file) {
    std::string ext = paths::extensionLower(file);
    ext.erase(std::remove_if(ext.begin(), ext.end(), [](char c) {
                  return !(std::isalnum(static_cast<unsigned char>(c)) || c == '.');
              }), ext.end());
    if (ext.size() > 12) ext.clear();
    return ext;
}

/// Lanza el trabajador y recoge su salida. `degraded` se activa si no se pudo aplicar el token restringido.
RunStatus runWorker(const IsolatedScanner::Options& opt, HANDLE hFile, const std::string& ext,
                    std::string& output, std::string& detail, bool& degraded) {
    output.clear();

    // Tubería de salida del trabajador (el extremo de lectura NO es heredable)
    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
    HANDLE r = nullptr, w = nullptr;
    if (!CreatePipe(&r, &w, &sa, 0)) { detail = "CreatePipe"; return RunStatus::StartFailed; }
    Handle pipeRead(r), pipeWrite(w);
    SetHandleInformation(pipeRead.get(), HANDLE_FLAG_INHERIT, 0);

    Handle nul(CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, nullptr));
    if (!nul.valid()) { detail = "NUL"; return RunStatus::StartFailed; }

    Handle job = makeJob(opt.memoryLimitBytes);
    if (!job.valid()) { detail = "Job"; return RunStatus::StartFailed; }

    // Lista explícita de handles heredables: el trabajador no recibe nada más del servicio
    HANDLE inherit[3] = {hFile, pipeWrite.get(), nul.get()};
    SIZE_T attrSize = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attrSize);
    std::vector<BYTE> attrBuf(attrSize);
    auto* attrs = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attrBuf.data());
    if (!InitializeProcThreadAttributeList(attrs, 1, 0, &attrSize)) { detail = "attrlist"; return RunStatus::StartFailed; }
    if (!UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherit, sizeof(inherit), nullptr, nullptr)) {
        DeleteProcThreadAttributeList(attrs);
        detail = "handlelist";
        return RunStatus::StartFailed;
    }

    STARTUPINFOEXW si{};
    si.StartupInfo.cb = sizeof(si);
    si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    si.StartupInfo.hStdInput = nul.get();
    si.StartupInfo.hStdOutput = pipeWrite.get();
    si.StartupInfo.hStdError = pipeWrite.get();
    si.lpAttributeList = attrs;

    char handleHex[32];
    std::snprintf(handleHex, sizeof(handleHex), "%llx", static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(hFile)));
    const std::string args = std::string("--handle ") + handleHex + (ext.empty() ? "" : " --ext " + ext);
    std::wstring cmd = L"\"" + opt.workerExe.wstring() + L"\" " + std::wstring(args.begin(), args.end());

    std::wstring cmdFallback = cmd; // CreateProcess puede modificar el búfer: el reintento usa una copia limpia
    // DETACHED_PROCESS: sin consola. Con CREATE_NO_WINDOW Windows crea conhost.exe como proceso hijo DENTRO del
    // Job Object, que solo admite un proceso activo, y el trabajador moriría al arrancar.
    const DWORD flags = EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | DETACHED_PROCESS;
    PROCESS_INFORMATION pi{};
    bool started = false;

    Handle token = makeSandboxToken();
    if (token.valid()) {
        started = CreateProcessAsUserW(token.get(), nullptr, cmd.data(), nullptr, nullptr, TRUE, flags, nullptr,
                                       nullptr, &si.StartupInfo, &pi) != 0;
    }
    if (!started) {
        // Respaldo degradado (p. ej. ejecución sin privilegios de servicio): mismo Job Object, mismo token del llamador
        degraded = true;
        started = CreateProcessW(nullptr, cmdFallback.data(), nullptr, nullptr, TRUE, flags, nullptr, nullptr,
                                 &si.StartupInfo, &pi) != 0;
    }
    DeleteProcThreadAttributeList(attrs);
    if (!started) { detail = "CreateProcess " + std::to_string(GetLastError()); return RunStatus::StartFailed; }

    Handle process(pi.hProcess), thread(pi.hThread);
    pipeWrite.reset(); // el servicio ya no escribe: así la lectura ve el final cuando el trabajador termina
    nul.reset();

    if (!AssignProcessToJobObject(job.get(), process.get())) {
        TerminateProcess(process.get(), 1);
        detail = "AssignProcessToJobObject " + std::to_string(GetLastError());
        return RunStatus::StartFailed;
    }
    ResumeThread(thread.get());

    // Recogida de salida con tiempo máximo (sondeo para poder cortar un trabajador colgado)
    const auto deadline = std::chrono::steady_clock::now() + opt.timeout;
    std::vector<char> buf(16 * 1024);
    bool exited = false;
    for (;;) {
        DWORD avail = 0;
        if (PeekNamedPipe(pipeRead.get(), nullptr, 0, nullptr, &avail, nullptr) && avail > 0) {
            DWORD got = 0;
            if (ReadFile(pipeRead.get(), buf.data(), static_cast<DWORD>(std::min<size_t>(buf.size(), avail)), &got, nullptr) && got > 0) {
                output.append(buf.data(), got);
                if (output.size() > kMaxOutputBytes) {
                    TerminateJobObject(job.get(), 1);
                    detail = "salida excesiva";
                    return RunStatus::BadOutput;
                }
            }
            continue;
        }
        if (exited) break;

        const DWORD wr = WaitForSingleObject(process.get(), 25);
        if (wr == WAIT_OBJECT_0) { exited = true; continue; } // una última pasada para vaciar la tubería
        if (std::chrono::steady_clock::now() > deadline) {
            TerminateJobObject(job.get(), 1);
            detail = "tiempo excedido";
            return RunStatus::Timeout;
        }
    }

    DWORD code = 1;
    GetExitCodeProcess(process.get(), &code);
    if (code != 0) {
        char hex[16];
        std::snprintf(hex, sizeof(hex), "0x%08lX", static_cast<unsigned long>(code));
        detail = std::string("codigo de salida ") + hex;
        return RunStatus::Crashed;
    }
    return RunStatus::Ok;
}

/// Ejecuta una orden oculta y espera su fin. @return código de salida, o -1 si no pudo lanzarse.
long runHiddenCommand(std::wstring cmd, DWORD timeoutMs) {
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) return -1;
    Handle process(pi.hProcess), thread(pi.hThread);
    if (WaitForSingleObject(process.get(), timeoutMs) != WAIT_OBJECT_0) {
        TerminateProcess(process.get(), 1);
        return -1;
    }
    DWORD code = 1;
    GetExitCodeProcess(process.get(), &code);
    return static_cast<long>(code);
}

} // namespace

bool IsolatedScanner::ensureNetworkBlock(const std::filesystem::path& workerExe, std::string& detail) {
    detail.clear();
    wchar_t sysDir[MAX_PATH]{};
    if (!GetSystemDirectoryW(sysDir, MAX_PATH)) { detail = "GetSystemDirectory"; return false; }
    const std::wstring netsh = L"\"" + std::wstring(sysDir) + L"\\netsh.exe\" advfirewall firewall ";
    const std::wstring name = L"name=\"OpenGuard Worker (sin red)\"";

    // Se recrean siempre: así la regla apunta a la ruta actual de instalación
    runHiddenCommand(netsh + L"delete rule " + name, 15000);

    const std::wstring program = L"program=\"" + workerExe.wstring() + L"\"";
    const long outRc = runHiddenCommand(netsh + L"add rule " + name + L" dir=out action=block " + program + L" enable=yes profile=any", 15000);
    const long inRc = runHiddenCommand(netsh + L"add rule " + name + L" dir=in action=block " + program + L" enable=yes profile=any", 15000);

    if (outRc != 0 || inRc != 0) {
        detail = "netsh devolvio " + std::to_string(outRc) + "/" + std::to_string(inRc) + " (se requieren privilegios de administrador)";
        return false;
    }
    return true;
}

IsolatedScanner::IsolatedScanner(std::shared_ptr<SignatureDB> db, Options options)
    : m_db(std::move(db)), m_options(std::move(options)) {}

bool IsolatedScanner::available() const {
    std::error_code ec;
    return !m_options.workerExe.empty() && std::filesystem::is_regular_file(m_options.workerExe, ec);
}

std::optional<ScanResult> IsolatedScanner::scan(const std::filesystem::path& filePath) const {
    ScanResult result;
    result.filePath = filePath;
    const auto t0 = std::chrono::high_resolution_clock::now();

    // 1. El servicio abre el archivo (solo lectura, heredable) y comprueba tipo y tamaño
    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
    Handle file(CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, &sa,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
    if (!file.valid()) {
        result.skipped = true;
        result.error = "Error de lectura: archivo inaccesible o bloqueado";
        return result;
    }
    LARGE_INTEGER size{};
    if (GetFileType(file.get()) != FILE_TYPE_DISK || !GetFileSizeEx(file.get(), &size)) {
        result.skipped = true;
        result.error = "No es un archivo regular";
        return result;
    }
    if (static_cast<uint64_t>(size.QuadPart) > m_options.maxFileBytes) {
        result.skipped = true;
        result.error = "Archivo excede el limite maximo configurado";
        return result;
    }

    // 2. Análisis de contenido en el proceso aislado
    std::string output, detail;
    bool degraded = false;
    const RunStatus status = runWorker(m_options, file.get(), sanitizeExtension(filePath), output, detail, degraded);
    if (degraded) m_degraded = true;

    if (status == RunStatus::StartFailed) return std::nullopt; // el llamador decide el respaldo

    ContentAnalysis content;
    bool parsed = (status == RunStatus::Ok) && contentAnalysisFromJson(output, content) && content.ok;

    if (!parsed) {
        // Un analizador que se cae o se cuelga con un archivo concreto es en sí un indicio sospechoso
        // Diagnóstico: el trabajador responde con JSON {"ok":false,"error":...} ante un fallo controlado
        ContentAnalysis reported;
        if (contentAnalysisFromJson(output, reported) && !reported.error.empty()) {
            detail += (detail.empty() ? "" : ": ") + reported.error.substr(0, 200);
        } else if (!output.empty()) {
            std::string snippet = output.substr(0, 120);
            for (char& c : snippet) if (static_cast<unsigned char>(c) < 32 || static_cast<unsigned char>(c) > 126) c = '?';
            detail += (detail.empty() ? "respuesta invalida" : "") + std::string(" | salida: ") + snippet;
        } else if (status == RunStatus::Ok) {
            detail = "respuesta vacia del trabajador";
        } else if (detail.empty()) {
            detail = "sin salida del trabajador";
        }
        result.addThreat("Heuristic.AnalyzerFailure", "isolation", "medium", 40,
                         "El analizador aislado no pudo procesar este archivo (" + detail + ")");
        result.scanTimeMs = std::chrono::duration<double, std::milli>(std::chrono::high_resolution_clock::now() - t0).count();
        return result;
    }

    result.sha256 = content.sha256;
    result.sha1 = content.sha1;
    result.md5 = content.md5;

    // 3. Base de firmas (servicio)
    if (m_db && m_db->isOpen()) {
        auto match = m_db->lookup(result.sha256, result.sha1, result.md5);
        if (match.has_value()) FileScanner::addSignatureMatch(result, *match);
    }

    // 4. Doble extensión
    if (FileScanner::hasDoubleExtension(filePath)) {
        result.addThreat("Heuristic.DoubleExtension", "heuristic", "medium", 40,
                         "El archivo utiliza una extension doble potencialmente enganosa");
    }

    // 4b. Ubicación sospechosa (se calcula aquí: el trabajador no conoce la ruta real)
    if (auto loc = HeuristicsEngine::suspiciousLocation(filePath)) {
        result.addThreat(loc->name, loc->method, loc->severity, loc->score, loc->details);
    }

    // 5. Detecciones del trabajador. Solo se aceptan métodos de contenido: un trabajador comprometido no
    //    puede fabricar una coincidencia de firma (hash_signature) que provoque un aislamiento automático.
    int weakSeen = 0;
    for (const auto& t : content.threats) {
        if (t.method != "yara" && t.method != "heuristic_script" && t.method != "heuristic_office") continue;
        const int s = HeuristicsEngine::weighContentMatch(filePath, t.method, t.severity, t.score, weakSeen);
        if (s < 0) continue; // libreria/desarrollo: cadenas tipicas de malware sin contexto
        result.addThreat(t.name.substr(0, 128), t.method, t.severity.substr(0, 16), s, t.details.substr(0, 1024));
    }

    // 6. PE: la firma Authenticode se verifica aquí (necesita servicios del sistema) y se aplica al informe
    if (content.isPE) {
        PEReport report;
        report.isValidPE = true;
        report.heuristicScore = content.peScore;
        report.anomalyReasons = content.peReasons;
        report.detectedPacker = content.peDetectedPacker.substr(0, 64);

        bool valid = false;
        std::wstring signer;
        const bool hasSignature = PEAnalyzer::verifyAuthenticodeSignature(filePath, valid, signer);
        PEAnalyzer::applySignatureResult(report, hasSignature, valid, signer);
        HeuristicsEngine::addPEThreat(report, result);
    }

    result.scanTimeMs = std::chrono::duration<double, std::milli>(std::chrono::high_resolution_clock::now() - t0).count();
    return result;
}

} // namespace openguard
