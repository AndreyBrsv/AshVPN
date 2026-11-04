; Complete per-user application bundle. User data and vault entries live elsewhere.
[Setup]
AppId=io.github.andreybrsv.ashapp
AppName=Ashapp
AppVersion={#AppVersion}
AppPublisher=Ashapp contributors
AppPublisherURL=https://github.com/AndreyBrsv/Ashapp
SetupIconFile="{#SourceRoot}\flutter\windows\runner\resources\app_icon.ico"
DefaultDirName={localappdata}\Programs\Ashapp
DefaultGroupName=Ashapp
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
DisableDirPage=yes
DisableProgramGroupPage=yes
UsePreviousAppDir=no
CloseApplications=no
RestartApplications=no
AppMutex=Ashapp.Desktop.Running
UninstallDisplayIcon={app}\ashapp.exe
LicenseFile={#SourceRoot}\LICENSE
OutputDir={#OutputDirectory}
OutputBaseFilename={#OutputName}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern

[Files]
Source: "{#SourceRoot}\flutter\build\windows\x64\runner\Release\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#SourceRoot}\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceRoot}\vendor\LICENSE.Varckin"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Ashapp"; Filename: "{app}\ashapp.exe"

[Registry]
Root: HKCU; Subkey: "Software\Ashapp"; ValueType: dword; ValueName: "MaintenanceVersion"; ValueData: "1"; Flags: uninsdeletevalue uninsdeletekeyifempty

[Run]
Filename: "{app}\ashapp.exe"; Description: "Open Ashapp"; Flags: nowait postinstall skipifsilent
Filename: "{app}\ashapp.exe"; Flags: nowait; Check: IsAppUpdate

[Code]
var
  Maintenance: TInputOptionWizardPage;
  EraseData: TNewCheckBox;

function HasSwitch(Value: String): Boolean;
var
  Index: Integer;
begin
  Result := False;
  for Index := 1 to ParamCount do
    if CompareText(ParamStr(Index), Value) = 0 then Result := True;
end;

function IsAppUpdate: Boolean;
begin
  Result := HasSwitch('/ASHAPPUPDATE');
end;

function InitializeSetup: Boolean;
var
  Attempts: Integer;
begin
  Result := True;
  if IsAppUpdate then begin
    { Never terminate the running application or any server task. }
    Attempts := 0;
    while CheckForMutexes('Ashapp.Desktop.Running') and (Attempts < 600) do begin
      Sleep(100);
      Attempts := Attempts + 1;
    end;
    Result := not CheckForMutexes('Ashapp.Desktop.Running');
  end;
end;

procedure InitializeWizard;
var
  Version: Cardinal;
begin
  if (not WizardSilent) and FileExists(ExpandConstant('{app}\unins000.exe')) then begin
    Maintenance := CreateInputOptionPage(wpWelcome, 'Maintain Ashapp',
      'Ashapp is already installed',
      'Update the application, or remove it from this computer. Your VPS servers are never changed.', True, False);
    Maintenance.Add('Update / repair Ashapp (keep all local data)');
    Maintenance.Add('Uninstall Ashapp');
    Maintenance.SelectedValueIndex := 0;
    Maintenance.CheckListBox.Height := ScaleY(80);
    EraseData := TNewCheckBox.Create(WizardForm);
    EraseData.Parent := Maintenance.Surface;
    EraseData.Top := Maintenance.CheckListBox.Top + Maintenance.CheckListBox.Height + ScaleY(8);
    EraseData.Width := Maintenance.SurfaceWidth;
    EraseData.Height := ScaleY(40);
    EraseData.Caption := 'Also delete local data and saved passwords';
    EraseData.Checked := False;
    if not RegQueryDWordValue(HKCU, 'Software\Ashapp', 'MaintenanceVersion', Version) then begin
      EraseData.Enabled := False;
      EraseData.Caption := 'Update once to enable local-data removal';
    end;
  end;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  Code: Integer;
  Parameters: String;
begin
  Result := True;
  if Assigned(Maintenance) and (CurPageID = Maintenance.ID) and
      (Maintenance.SelectedValueIndex = 1) then begin
    if EraseData.Checked then begin
      if MsgBox('Uninstall Ashapp and permanently delete local servers, templates and protected passwords? VPS servers and exported files remain unchanged.',
          mbConfirmation, MB_YESNO or MB_DEFBUTTON2) <> IDYES then begin
        Result := False;
        exit;
      end;
    end else if MsgBox('Uninstall Ashapp? Local settings and passwords will be kept. VPS servers remain unchanged.',
        mbConfirmation, MB_YESNO or MB_DEFBUTTON2) <> IDYES then begin
      Result := False;
      exit;
    end;
    { Final approval happened above. Silent uninstall has no later confirmation
      that could be cancelled after deleting credentials. }
    Parameters := '/SILENT /ASHAPPMAINTENANCE';
    if EraseData.Checked then Parameters := Parameters + ' /ERASELOCALDATA';
    if Exec(ExpandConstant('{app}\unins000.exe'), Parameters, '', SW_SHOWNORMAL,
        ewWaitUntilTerminated, Code) and (Code = 0) then begin
      WizardForm.Close;
    end else begin
      MsgBox('Ashapp was not removed. Close all Ashapp windows and try again. If protected storage is locked, unlock it first.', mbError, MB_OK);
    end;
    Result := False;
  end;
end;

function InitializeUninstall: Boolean;
var
  Code: Integer;
begin
  Result := False;
  if CheckForMutexes('Ashapp.Desktop.Running') then begin
    MsgBox('Close Ashapp before uninstalling. Server tasks will not be stopped automatically.', mbError, MB_OK);
    exit;
  end;
  if HasSwitch('/ERASELOCALDATA') then begin
    { InitializeUninstall can reliably abort even on Inno Setup 6. Only the
      already-confirmed Setup maintenance flow requests destructive cleanup. }
    if not UninstallSilent or not HasSwitch('/ASHAPPMAINTENANCE') then begin
      MsgBox('Use Ashapp Setup and its local-data checkbox for full removal.', mbError, MB_OK);
      exit;
    end;
    if not Exec(ExpandConstant('{app}\ashapp.exe'), '--erase-local-data', '', SW_HIDE,
        ewWaitUntilTerminated, Code) or (Code <> 0) then begin
      MsgBox('Local data could not be completely removed. Uninstallation has been stopped so that protected credentials remain accessible. Unlock protected storage and retry.', mbError, MB_OK);
      exit;
    end;
  end;
  Result := True;
end;
