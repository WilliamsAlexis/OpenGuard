; ==============================================================================
; Script de Inno Setup para OpenGuard Antivirus (Windows 10/11)
; Genera el instalador oficial OpenGuard_Setup.exe
; ==============================================================================

#define MyAppName "OpenGuard Antivirus"
#define MyAppVersion "0.1.0"
#define MyAppPublisher "Alexis Williams"
#define MyAppURL "https://github.com/WilliamsAlexis/OpenGuard"
#define MyAppExeName "openguard_cli.exe"
#define MyServiceExeName "openguard_service.exe"

[Setup]
AppId={{9F571B39-8652-4F11-9A74-C25E2D0C4EA1}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\OpenGuard
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
LicenseFile=LICENSE
OutputDir=dist
OutputBaseFilename=OpenGuard_Setup_v0.1.0
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin

[Languages]
Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
; Binarios principales compilados
Source: "build\src\cli\Release\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "build\src\service\Release\{#MyServiceExeName}"; DestDir: "{app}"; Flags: ignoreversion

; Base de firmas y reglas YARA
Source: "signatures\hashes_index.json"; DestDir: "{app}\signatures"; Flags: ignoreversion
Source: "signatures\manifest.sha256"; DestDir: "{app}\signatures"; Flags: ignoreversion
Source: "signatures\yara_rules\*"; DestDir: "{app}\signatures\yara_rules"; Flags: ignoreversion recursesubdirs createallsubdirs

; Documentación y licencias
Source: "README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "PRIVACY.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName} Consola"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Desinstalar {#MyAppName}"; Filename: "{uninstallexe}"

[Run]
; Registrar e iniciar el servicio en segundo plano de Windows al finalizar la instalacion
Filename: "{app}\{#MyServiceExeName}"; Parameters: "--install"; Flags: runhidden waituntilterminated

[UninstallRun]
; Detener y remover el servicio de Windows antes de eliminar los archivos
Filename: "{app}\{#MyServiceExeName}"; Parameters: "--uninstall"; Flags: runhidden waituntilterminated

