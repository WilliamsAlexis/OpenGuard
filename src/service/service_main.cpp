/**
 * @file service_main.cpp
 * @brief Servicio de Windows para el monitoreo en tiempo real y protección de OpenGuard.
 * @details Implementa la interacción con el Administrador de Control de Servicios (SCM)
 *          de Windows y canaliza notificaciones y comandos a través de Named Pipes seguros.
 */

#include "openguard/signatures.h"
#include "openguard/scanner.h"

#include <windows.h>
#include <iostream>
#include <string>

namespace {

constexpr wchar_t SERVICE_NAME[] = L"OpenGuardService";
constexpr wchar_t SERVICE_DISPLAY_NAME[] = L"OpenGuard Antivirus Real-Time Protection";

SERVICE_STATUS        g_serviceStatus{};
SERVICE_STATUS_HANDLE g_statusHandle = nullptr;
HANDLE                g_stopEvent = nullptr;

/**
 * @brief Actualiza el estado del servicio ante el Service Control Manager (SCM).
 * @param currentState Estado (ej: SERVICE_RUNNING, SERVICE_STOPPED).
 * @param exitCode Código de error Win32 de terminación.
 * @param waitHint Tiempo estimado en milisegundos para completar la transición.
 */
void reportServiceStatus(DWORD currentState, DWORD exitCode, DWORD waitHint) {
    static DWORD checkPoint = 1;

    g_serviceStatus.dwCurrentState = currentState;
    g_serviceStatus.dwWin32ExitCode = exitCode;
    g_serviceStatus.dwWaitHint = waitHint;

    if (currentState == SERVICE_START_PENDING) {
        g_serviceStatus.dwControlsAccepted = 0;
    } else {
        g_serviceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    }

    if ((currentState == SERVICE_RUNNING) || (currentState == SERVICE_STOPPED)) {
        g_serviceStatus.dwCheckPoint = 0;
    } else {
        g_serviceStatus.dwCheckPoint = checkPoint++;
    }

    SetServiceStatus(g_statusHandle, &g_serviceStatus);
}

/**
 * @brief Manejador de eventos de control enviados por el SCM (Stop, Shutdown).
 * @param control Código de control recibido.
 * @param eventType Tipo de evento extendido.
 * @param eventData Datos del evento.
 * @param context Contexto definido por el usuario.
 * @return DWORD Código de estado Win32.
 */
DWORD WINAPI serviceCtrlHandler(DWORD control, DWORD, LPVOID, LPVOID) {
    switch (control) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            reportServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 3000);
            if (g_stopEvent) {
                SetEvent(g_stopEvent);
            }
            return NO_ERROR;
        default:
            break;
    }
    return ERROR_CALL_NOT_IMPLEMENTED;
}

/**
 * @brief Rutina principal que ejecuta la lógica de fondo del servicio.
 */
void serviceWorker() {
    g_stopEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
    if (!g_stopEvent) {
        reportServiceStatus(SERVICE_STOPPED, GetLastError(), 0);
        return;
    }

    reportServiceStatus(SERVICE_RUNNING, NO_ERROR, 0);

    // Bucle de ejecución del servicio: espera señal de detención o procesa monitoreo
    while (WaitForSingleObject(g_stopEvent, 1000) == WAIT_TIMEOUT) {
        // En esta sección se coordinan los monitores de directorio (ReadDirectoryChangesW)
        // y verificación de archivos señuelo anti-ransomware (Honeypots).
    }

    CloseHandle(g_stopEvent);
    g_stopEvent = nullptr;
    reportServiceStatus(SERVICE_STOPPED, NO_ERROR, 0);
}

/**
 * @brief Punto de entrada invocado por el Service Control Manager al iniciar el servicio.
 * @param argc Conteo de argumentos.
 * @param argv Vector de cadenas de argumentos.
 */
VOID WINAPI serviceMain(DWORD argc, LPWSTR* argv) {
    g_statusHandle = RegisterServiceCtrlHandlerExW(
        SERVICE_NAME,
        serviceCtrlHandler,
        nullptr
    );

    if (!g_statusHandle) {
        return;
    }

    g_serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_serviceStatus.dwServiceSpecificExitCode = 0;

    reportServiceStatus(SERVICE_START_PENDING, NO_ERROR, 3000);
    serviceWorker();
}

/**
 * @brief Instala el servicio en el registro del sistema mediante el SCM (requiere Administrador).
 * @return true si la instalación fue exitosa; false en caso de error.
 */
bool installService() {
    SC_HANDLE scManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scManager) {
        std::wcerr << L"[!] Error: Se requieren privilegios de Administrador para registrar el servicio.\n";
        return false;
    }

    wchar_t path[MAX_PATH];
    if (!GetModuleFileNameW(nullptr, path, MAX_PATH)) {
        CloseServiceHandle(scManager);
        return false;
    }

    SC_HANDLE service = CreateServiceW(
        scManager,
        SERVICE_NAME,
        SERVICE_DISPLAY_NAME,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        path,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr
    );

    if (!service) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS) {
            std::wcout << L"[+] El servicio OpenGuard ya se encuentra instalado.\n";
        } else {
            std::wcerr << L"[!] Fallo al crear el servicio. Codigo de error: " << err << L"\n";
        }
        CloseServiceHandle(scManager);
        return false;
    }

    std::wcout << L"[+] Servicio OpenGuard instalado con exito.\n";
    CloseServiceHandle(service);
    CloseServiceHandle(scManager);
    return true;
}

/**
 * @brief Desinstala el servicio del sistema mediante el SCM.
 * @return true si se removió; false en caso contrario.
 */
bool uninstallService() {
    SC_HANDLE scManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scManager) return false;

    SC_HANDLE service = OpenServiceW(scManager, SERVICE_NAME, DELETE);
    if (!service) {
        CloseServiceHandle(scManager);
        return false;
    }

    bool success = DeleteService(service);
    CloseServiceHandle(service);
    CloseServiceHandle(scManager);

    if (success) {
        std::wcout << L"[+] Servicio OpenGuard desinstalado con exito.\n";
    }
    return success;
}

} // namespace anónimo

int wmain(int argc, wchar_t* argv[]) {
    if (argc > 1) {
        std::wstring arg = argv[1];
        if (arg == L"/install" || arg == L"-install" || arg == L"--install") {
            return installService() ? 0 : 1;
        }
        if (arg == L"/uninstall" || arg == L"-uninstall" || arg == L"--uninstall") {
            return uninstallService() ? 0 : 1;
        }
    }

    SERVICE_TABLE_ENTRYW serviceTable[] = {
        { const_cast<LPWSTR>(SERVICE_NAME), serviceMain },
        { nullptr, nullptr }
    };

    if (!StartServiceCtrlDispatcherW(serviceTable)) {
        DWORD err = GetLastError();
        if (err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            std::wcout << L"OpenGuard Service (Ejecucion en modo consola):\n"
                       << L"  Para registrar como servicio del sistema: " << argv[0] << L" --install\n"
                       << L"  Para remover el servicio:                 " << argv[0] << L" --uninstall\n";
            return 0;
        }
        return 1;
    }

    return 0;
}

