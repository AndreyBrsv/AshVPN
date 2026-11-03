; Complete per-user application bundle. User data and vault entries live elsewhere.
[Setup]
AppId=io.github.andreybrsv.ashapp
AppName=Ashapp
AppVersion={#AppVersion}
AppPublisher=Ashapp contributors
AppPublisherURL=https://github.com/AndreyBrsv/Ashapp
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

[Run]
Filename: "{app}\ashapp.exe"; Description: "Open Ashapp"; Flags: nowait postinstall skipifsilent
