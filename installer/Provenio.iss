; Установщик Provenio (Inno Setup 6).
; Сборка: ISCC.exe /DAppVersion=2.2.0 installer\Provenio.iss  ->  installer\Output\Provenio-Setup-2.2.0.exe
; Без прав администратора ставится в %LOCALAPPDATA%\Programs\Provenio (можно выбрать «для всех пользователей»).

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#define AppName "Provenio"
#define AppExe "Provenio.exe"

[Setup]
AppId={{6F1C2B8E-5D3A-4C7B-9E21-7A4D0C3B9F55}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher=nzikach
AppPublisherURL=https://github.com/nzikach/Provenio-OSINT-Tool
AppSupportURL=https://github.com/nzikach/Provenio-OSINT-Tool/issues
AppUpdatesURL=https://github.com/nzikach/Provenio-OSINT-Tool/releases
VersionInfoVersion={#AppVersion}
VersionInfoProductVersion={#AppVersion}
VersionInfoDescription={#AppName} {#AppVersion} Setup
VersionInfoCompany=nzikach
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
LicenseFile=TERMS.txt
OutputDir=Output
OutputBaseFilename=Provenio-Setup-{#AppVersion}
SetupIconFile=..\assets\provenio.ico
UninstallDisplayIcon={app}\{#AppExe}
UninstallDisplayName={#AppName} {#AppVersion}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "ru"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "en"; MessagesFile: "compiler:Default.isl"

[CustomMessages]
ru.DesktopIcon=Создать значок на рабочем столе
en.DesktopIcon=Create a desktop shortcut
ru.Docs=Условия и конфиденциальность
en.Docs=Terms and privacy
ru.RemoveData=Удалить также ваши данные Provenio (аккаунт, кейсы, снимки, ключи API)?%n%nПапка: %1%n%nНажмите «Нет», чтобы сохранить их для повторной установки.
en.RemoveData=Also delete your Provenio data (account, cases, snapshots, API keys)?%n%nFolder: %1%n%nChoose "No" to keep it for a later reinstall.

[Tasks]
; значок на рабочем столе — по желанию, по умолчанию не отмечен
Name: "desktopicon"; Description: "{cm:DesktopIcon}"; Flags: unchecked

[Files]
Source: "..\dist\{#AppExe}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\legal\*.md"; DestDir: "{app}\legal"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{autoprograms}\{#AppName} — {cm:Docs}"; Filename: "{app}\legal"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExe}"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent

[Code]
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  DataDir: String;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    DataDir := ExpandConstant('{localappdata}\Provenio');
    if DirExists(DataDir) and not UninstallSilent then
      { по умолчанию — «Нет»: данные сохраняются }
      if SuppressibleMsgBox(FmtMessage(CustomMessage('RemoveData'), [DataDir]),
           mbConfirmation, MB_YESNO or MB_DEFBUTTON2, IDNO) = IDYES then
        DelTree(DataDir, True, True, True);
  end;
end;
