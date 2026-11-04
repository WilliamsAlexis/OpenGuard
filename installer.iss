; ==============================================================================
; Script de Inno Setup para OpenGuard Antivirus (Windows 10/11 x64)
; Genera dist\OpenGuard_Setup_v<version>.exe
;
; Uso recomendado (compila el proyecto y prepara los binarios en dist\stage):
;     powershell -File scripts\build_installer.ps1
;
; Uso manual (si ya compilo y copio los .exe a dist\stage):
;     ISCC.exe /DStageDir=dist\stage /DMyAppVersion=0.4.1 installer.iss
; ==============================================================================

#ifndef MyAppVersion
  #define MyAppVersion "0.4.1"
#endif
#ifndef StageDir
  #define StageDir "dist\stage"
#endif

#define MyAppName "OpenGuard Antivirus"
#define MyAppPublisher "Alexis Williams"
#define MyAppURL "https://github.com/WilliamsAlexis/OpenGuard"
#define MyAppExeName "openguard_cli.exe"
#define MyServiceExeName "openguard_service.exe"
#define MyServiceName "OpenGuardService"
#define MyGuiExeName "openguard_gui.exe"

[Setup]
; GUID fijo: identifica la aplicacion para actualizaciones sobre una instalacion previa
AppId={{9F571B39-8652-4F11-9A74-C25E2D0C4EA1}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}/issues
AppUpdatesURL={#MyAppURL}/releases
VersionInfoVersion={#MyAppVersion}
DefaultDirName={autopf}\OpenGuard
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
LicenseFile=LICENSE
OutputDir=dist
OutputBaseFilename=OpenGuard_Setup_v{#MyAppVersion}
UninstallDisplayIcon={app}\{#MyGuiExeName}
SetupIconFile=assets\openguard.ico
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
PrivilegesRequired=admin
ChangesEnvironment=yes

[Languages]
Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[CustomMessages]
spanish.TaskAutostart=Iniciar OpenGuard en segundo plano al iniciar sesion (icono en la bandeja, avisos y analisis de unidades USB)
english.TaskAutostart=Start OpenGuard in the background at sign-in (tray icon, alerts and USB drive scanning)
spanish.TaskAddToPath=Agregar OpenGuard al PATH del sistema (permite ejecutar "openguard_cli" desde cualquier terminal)
english.TaskAddToPath=Add OpenGuard to the system PATH (lets you run "openguard_cli" from any terminal)
spanish.IconQuickScan=Analisis rapido
english.IconQuickScan=Quick scan
spanish.IconConsole=Consola de OpenGuard
english.IconConsole=OpenGuard console
spanish.IconUninstall=Desinstalar OpenGuard
english.IconUninstall=Uninstall OpenGuard
spanish.RunQuickScan=Ejecutar un analisis rapido ahora
english.RunQuickScan=Run a quick scan now
spanish.StatusDatabase=Inicializando la base de firmas...
english.StatusDatabase=Initializing the signature database...
spanish.StatusService=Registrando e iniciando la proteccion en tiempo real...
english.StatusService=Registering and starting real-time protection...
spanish.AskRemoveData=Desea eliminar tambien la base de firmas, el registro y la CUARENTENA de OpenGuard?%n%nSi elige Si, los archivos aislados se perderan definitivamente.
english.AskRemoveData=Do you also want to delete the OpenGuard signature database, logs and QUARANTINE vault?%n%nIf you choose Yes, isolated files will be permanently lost.

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "addtopath"; Description: "{cm:TaskAddToPath}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "autostart"; Description: "{cm:TaskAutostart}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
; Binarios principales (compilados con el runtime estatico: no requieren VC++ Redistributable)
Source: "{#StageDir}\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#StageDir}\{#MyServiceExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#StageDir}\{#MyGuiExeName}"; DestDir: "{app}"; Flags: ignoreversion
; Proceso aislado de analisis (el servicio lo lanza con token restringido e integridad baja)
Source: "{#StageDir}\openguard_worker.exe"; DestDir: "{app}"; Flags: ignoreversion

; Base de firmas y reglas
Source: "signatures\hashes_index.json"; DestDir: "{app}\signatures"; Flags: ignoreversion
Source: "signatures\manifest.sha256"; DestDir: "{app}\signatures"; Flags: ignoreversion
Source: "signatures\yara_rules\*"; DestDir: "{app}\signatures\yara_rules"; Flags: ignoreversion recursesubdirs createallsubdirs

; Documentacion y licencias
Source: "README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "PRIVACY.md"; DestDir: "{app}"; Flags: ignoreversion

[Dirs]
; Datos mutables (base de firmas, cuarentena, registros). Solo Administradores/SYSTEM pueden modificarlos:
; asi un proceso sin privilegios no puede alterar las firmas ni la boveda. Los usuarios solo leen.
Name: "{commonappdata}\OpenGuard"; Permissions: admins-full system-full users-readexec

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyGuiExeName}"; WorkingDir: "{app}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyGuiExeName}"; WorkingDir: "{app}"; Tasks: desktopicon
Name: "{group}\{cm:IconQuickScan}"; Filename: "{cmd}"; Parameters: "/k """"{app}\{#MyAppExeName}"" quick"""; WorkingDir: "{app}"; Comment: "OpenGuard quick scan"
Name: "{group}\{cm:IconConsole}"; Filename: "{cmd}"; Parameters: "/k """"{app}\{#MyAppExeName}"" --help"""; WorkingDir: "{app}"
Name: "{group}\{cm:IconUninstall}"; Filename: "{uninstallexe}"

[Registry]
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment";  ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}";  Tasks: addtopath; Check: NeedsAddPath(ExpandConstant('{app}'))

[Run]
; 1) Crear/actualizar la base de firmas (como Administrador, para que el servicio y el CLI la compartan)
Filename: "{app}\{#MyAppExeName}"; Parameters: "update"; Flags: runhidden waituntilterminated; StatusMsg: "{cm:StatusDatabase}"
; 1b) Bloquear la red del proceso de analisis aislado (el servicio tambien renueva estas reglas al iniciar)
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""OpenGuard Worker (sin red)"""; Flags: runhidden waituntilterminated
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall add rule name=""OpenGuard Worker (sin red)"" dir=out action=block program=""{app}\openguard_worker.exe"" enable=yes profile=any"; Flags: runhidden waituntilterminated
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall add rule name=""OpenGuard Worker (sin red)"" dir=in action=block program=""{app}\openguard_worker.exe"" enable=yes profile=any"; Flags: runhidden waituntilterminated
; 2) Registrar e iniciar la proteccion en tiempo real
Filename: "{app}\{#MyServiceExeName}"; Parameters: "--install"; Flags: runhidden waituntilterminated; StatusMsg: "{cm:StatusService}"
; 2b) Inicio en segundo plano al iniciar sesion (tarea programada con privilegios elevados: sin pedir permiso cada vez)
Filename: "{sys}\schtasks.exe"; Parameters: "/Create /TN ""OpenGuard Tray"" /TR ""\""{app}\openguard_gui.exe\"" --tray"" /SC ONLOGON /RL HIGHEST /F"; Flags: runhidden waituntilterminated; Tasks: autostart
; 3) Opcional: lanzar un analisis rapido al terminar
Filename: "{cmd}"; Parameters: "/k """"{app}\{#MyAppExeName}"" quick"""; WorkingDir: "{app}";  Description: "{cm:RunQuickScan}"; Flags: postinstall nowait skipifsilent unchecked

[UninstallRun]
; Detiene y remueve el servicio antes de eliminar los archivos
Filename: "{app}\{#MyServiceExeName}"; Parameters: "--uninstall"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveOpenGuardService"
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""OpenGuard Worker (sin red)"""; Flags: runhidden waituntilterminated; RunOnceId: "RemoveWorkerFirewallRule"
Filename: "{sys}\schtasks.exe"; Parameters: "/Delete /TN ""OpenGuard Tray"" /F"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveTrayTask"

[Code]
const
  EnvironmentKey = 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment';

{ Indica si la ruta aun no esta en el PATH del sistema (comparacion exacta entre separadores) }
function NeedsAddPath(Param: string): Boolean;
var
  OrigPath: string;
begin
  if not RegQueryStringValue(HKEY_LOCAL_MACHINE, EnvironmentKey, 'Path', OrigPath) then
  begin
    Result := True;
    exit;
  end;
  Result := Pos(';' + Uppercase(Param) + ';', ';' + Uppercase(OrigPath) + ';') = 0;
end;

{ Quita la ruta de instalacion del PATH del sistema al desinstalar }
procedure RemoveFromPath(const Dir: string);
var
  OrigPath, Target, NewPath: string;
  P: Integer;
begin
  if not RegQueryStringValue(HKEY_LOCAL_MACHINE, EnvironmentKey, 'Path', OrigPath) then
    exit;

  Target := ';' + Uppercase(Dir) + ';';
  NewPath := ';' + OrigPath + ';';
  P := Pos(Target, Uppercase(NewPath));
  if P = 0 then
    exit;

  Delete(NewPath, P, Length(Target) - 1);   { deja un ';' como separador }
  { Normalizar los ';' de los extremos agregados arriba }
  if (Length(NewPath) > 0) and (NewPath[1] = ';') then
    Delete(NewPath, 1, 1);
  if (Length(NewPath) > 0) and (NewPath[Length(NewPath)] = ';') then
    Delete(NewPath, Length(NewPath), 1);

  RegWriteExpandStringValue(HKEY_LOCAL_MACHINE, EnvironmentKey, 'Path', NewPath);
end;

{ Antes de copiar archivos: si hay una version anterior ejecutandose como servicio, detenerla
  para que sus .exe no esten bloqueados (actualizacion en sitio). }
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  { La aplicacion puede estar en segundo plano (bandeja): se cierra para poder reemplazar sus archivos }
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM openguard_gui.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\net.exe'), 'stop {#MyServiceName}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Result := '';
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  DataDir: string;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    RemoveFromPath(ExpandConstant('{app}'));

    DataDir := ExpandConstant('{commonappdata}\OpenGuard');
    if DirExists(DataDir) then
    begin
      { En desinstalacion silenciosa se conservan los datos (no hay usuario que decida) }
      if (not UninstallSilent) and (MsgBox(CustomMessage('AskRemoveData'), mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES) then
        DelTree(DataDir, True, True, True);
    end;
  end;
end;
