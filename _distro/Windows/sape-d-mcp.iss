; SAPÉ d-MCP — Inno Setup script for the Windows installer.
;
; Do not compile this file by hand: build_windows.ps1 builds the PyInstaller bundle first
; and then runs ISCC with the defines below. Saved as UTF-8 with a BOM so ISCC reads the
; accented "É" correctly.
;
; Install scope: per-user only (PrivilegesRequired=lowest, no override). The three
; databases are created in the current working directory (src/sape_d_mcp/db_location.py),
; so every shortcut sets its working directory to a per-user data folder under
; {localappdata}. That constant expands at install time, so it is only right for the
; user who ran the installer — which is exactly the per-user case. An all-users install
; would bake one user's path into shortcuts shared by everybody, hence no admin mode.

#ifndef AppVersion
  #error AppVersion must be defined (run build_windows.ps1)
#endif
#ifndef AppVersionDisplay
  #define AppVersionDisplay AppVersion
#endif
#ifndef SourceDir
  #error SourceDir (the PyInstaller onedir bundle) must be defined (run build_windows.ps1)
#endif
; SignToolName is defined only when build_windows.ps1 signs; it names the /S sign tool.

#define AppName "SAPÉ d-MCP"
#define AppExeName "sape-d-mcp.exe"
#define AppPublisher "SAPÉ smart bud"
#define AppURL "https://sapebud.com"
#define DataDir "{localappdata}\SAPE\d-MCP"
#define ProjectRoot "..\.."

[Setup]
; Never change AppId: it is how upgrades and the uninstaller find an existing install.
AppId={{6F4B2C1E-8A3D-4E5F-9B7C-2D1A0E3F5C84}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersionDisplay}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}
AppUpdatesURL={#AppURL}
DefaultDirName={autopf}\SAPE d-MCP
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
LicenseFile={#ProjectRoot}\LICENSE
SetupIconFile={#ProjectRoot}\gui_resources\icons\app.ico
UninstallDisplayIcon={app}\{#AppExeName}
UninstallDisplayName={#AppName}
OutputBaseFilename=sape-d-mcp-{#AppVersion}-windows-x64-setup
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
VersionInfoVersion={#AppVersion}
VersionInfoProductName={#AppName}
VersionInfoCompany={#AppPublisher}
VersionInfoCopyright=Copyright (C) 2026 Luciano Arrezze — GPL-3.0-only
#ifdef SignToolName
SignTool={#SignToolName}
SignedUninstaller=yes
#endif

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Dirs]
; The user's databases live here. Never removed on uninstall.
Name: "{#DataDir}"; Flags: uninsneveruninstall

[InstallDelete]
; An upgrade replaces the whole bundle: stale DLLs or modules left over from the previous
; version would otherwise sit next to the new ones inside _internal\.
Type: filesandordirs; Name: "{app}\_internal"

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExeName}"; WorkingDir: "{#DataDir}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; WorkingDir: "{#DataDir}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExeName}"; WorkingDir: "{#DataDir}"; Description: "{cm:LaunchProgram,{#StringChange(AppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent
