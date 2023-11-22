@echo off
cd "%~dp0"
set version=2.1.1

::Enable Delayed Expansion
setlocal EnableDelayedExpansion

::Timer Resolution
if not exist "SetTimerResolution.exe" exit 1

::NVProfileInspector
if not exist "nvidiaProfileInspector\nvidiaProfileInspector.exe" exit 3

::Admin
dism>nul||exit 4

::Check GPU
for /f "tokens=2 delims==" %%a in ('wmic path Win32_VideoController get VideoProcessor /value') do (
for %%n in (GeForce NVIDIA RTX GTX) do echo %%a | find /I "%%n" >nul && set GPU=NVIDIA
)

::Clear Nvidia Profile
del /F /Q "nvidiaProfileInspector\CoutXProfile.nip" 2>nul

::Enable Detailed BSOD
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v "DisplayParameters" /t REG_DWORD /d "1" /f >nul 2>&1
echo Enable Detailed BSOD

::Remove Potential GameDVR and FSO Overrides
Reg delete "HKLM\System\CurrentControlSet\Control\Session Manager\Environment" /v "__COMPAT_LAYER" /f >nul 2>&1
Reg delete "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehavior" /f >nul 2>&1
Reg delete "HKCU\System\GameConfigStore" /v "GameDVR_DSEBehavior" /f >nul 2>&1
Reg delete "HKLM\System\GameConfigStore" /f >nul 2>&1
Reg delete "HKU\.Default\System\GameConfigStore" /f >nul 2>&1
Reg delete "HKU\S-1-5-19\System\GameConfigStore" /f >nul 2>&1
Reg delete "HKU\S-1-5-20\System\GameConfigStore" /f >nul 2>&1
Reg delete "HKCU\Software\Classes\System\GameConfigStore" /f >nul 2>&1

::Disable GameDVR
Reg add HKCU\System\GameConfigStore /v GameDVR_Enabled /t REG_DWORD /d 0 /f >nul
Reg add HKCU\Software\Policies\Microsoft\Windows\GameDVR /v AllowGameDVR /t REG_DWORD /d 0 /f >nul
Reg add HKLM\Software\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR /v value /t REG_DWORD /d 0 /f >nul
::Disable GameDVR Capture
Reg add HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR /v AppCaptureEnabled /t REG_DWORD /d 0 /f >nul
Reg add HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR /v AudioCaptureEnabled /t REG_DWORD /d 0 /f >nul
Reg add HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR /v CursorCaptureEnabled /t REG_DWORD /d 0 /f >nul
Reg add HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR /v MicrophoneCaptureEnabled /t REG_DWORD /d 0 /f >nul
Reg add HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR /v HistoricalCaptureEnabled /t REG_DWORD /d 0 /f >nul
::Disable Game Bar Shortcuts
Reg add HKCU\Software\Microsoft\GameBar /v UseNexusForGameBarEnabled /t REG_DWORD /d 0 /f >nul
Reg add HKCU\Software\Microsoft\GameBar /v GamepadDoublePressIntervalMs /t REG_DWORD /d 0 /f >nul
Reg add HKCU\Software\Microsoft\GameBar /v ShowStartupPanel /t REG_DWORD /d 0 /f >nul
Reg add HKCU\Software\Microsoft\GameBar /v GamePanelStartupTipIndex /t REG_DWORD /d 0 /f >nul
::Disable Game Bar Presence Writer
Reg add "HKLM\Software\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.GameBar.PresenceServer.Internal.PresenceWriter" /v "ActivationType" /t REG_DWORD /d "0" /f >nul 2>&1
echo Disable GameDVR

::Enable GameDVR FSO
Reg add HKCU\System\GameConfigStore /v GameDVR_FSEBehaviorMode /t REG_DWORD /d 2 /f >nul
Reg add HKCU\System\GameConfigStore /v GameDVR_EFSEFeatureFlags /t REG_DWORD /d 0 /f >nul
Reg add HKCU\System\GameConfigStore /v GameDVR_DXGIHonorFSEWindowsCompatible /t REG_DWORD /d 0 /f >nul
Reg add HKCU\System\GameConfigStore /v GameDVR_HonorUserFSEBehaviorMode /t REG_DWORD /d 1 /f >nul
echo Enable GameDVR FSO

::Enable Windows VRR
call :DirectXSetting VRROptimizeEnable 1
echo Enable Windows VRR

::Enable Windowed Optimizations
call :DirectXSetting SwapEffectUpgradeEnable 1
Reg add HKCU\Software\Microsoft\DirectX\GraphicsSettings /v SwapEffectUpgradeCache /t REG_DWORD /d 1 /f >nul
echo Enable Windowed Optimizations

::https://docs.microsoft.com/en-us/windows-hardware/drivers/display/gdi-hardware-acceleration
for /f %%a in ('Reg query "HKLM\System\CurrentControlSet\Control\Class" /v "VgaCompatible" /s 2^>nul ^| findstr "HKEY"') do call :ControlSet "%%a" "KMD_EnableGDIAcceleration" "1"
::Enable Hardware Accelerated Scheduling
call :ControlSet "Control\GraphicsDrivers" "HwSchMode" "2"
echo Enable Hardware Accelerated Scheduling

::Allow Unrestricted Nvidia Clocks
nvidia-smi -acp UNRESTRICTED >nul 2>&1
echo Allow Unrestricted Nvidia Clocks

::Animations
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d "3" /f >nul
Reg add "HKCU\Control Panel\Desktop" /f /v "UserPreferencesMask" /t REG_BINARY /d "9012078012000000" >nul
Reg add "HKCU\Control Panel\Desktop" /v "DragFullWindows" /t REG_SZ /d "1" /f >nul
Reg add "HKCU\Control Panel\Desktop" /v "FontSmoothing" /t REG_SZ /d "2" /f >nul
Reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /t REG_SZ /d "0" /f >nul
Reg add "HKCU\Software\Microsoft\Windows\DWM" /v "EnableAeroPeek" /t REG_DWORD /d "0" /f >nul
Reg add "HKCU\Software\Microsoft\Windows\DWM" /v "AlwaysHibernateThumbnails" /t REG_DWORD /d "0" /f >nul
Reg add "HKCU\Software\Microsoft\Windows\DWM" /v "ListviewShadow" /t REG_DWORD /d "0" /f >nul
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "IconsOnly" /t REG_DWORD /d "0" /f >nul
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewAlphaSelect" /t REG_DWORD /d "0" /f >nul
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAnimations" /t REG_DWORD /d "0" /f >nul
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewShadow" /t REG_DWORD /d "0" /f >nul
echo Animations

::Quick Boot
Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "DelayedDesktopSwitchTimeout" /t REG_DWORD /d "0" /f >nul
Reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v "StartupDelayInMSec" /t REG_SZ /d "0" /f >nul
Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "RunStartupScriptSync" /t REG_DWORD /d "0" /f >nul
bcdedit /set bootuxdisabled on >nul
bcdedit /set bootmenupolicy standard >nul
bcdedit /set quietboot yes >nul
echo Quick Boot

::Quick Shutdown
rem Quickly kill apps during shutdown
Reg add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "2000" /f >nul
rem Quickly end services at shutdown
Reg add "HKLM\System\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "2000" /f >nul
rem Kill apps at shutdown
Reg add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f >nul
echo Quick Shutdown

::Quickly kill non-responsive apps
Reg add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f >nul
::Quickly show menus
Reg add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "20" /f >nul
echo Speed-up Windows

::Disable Telemetry
rem Bypass Win11 Checks
Reg add "HKLM\System\Setup\LabConfig" /v "BypassTPMCheck" /t REG_DWORD /d "1" /f >nul
Reg add "HKLM\System\Setup\LabConfig" /v "BypassRAMCheck" /t REG_DWORD /d "1" /f >nul
Reg add "HKLM\System\Setup\LabConfig" /v "BypassSecureBootCheck" /t REG_DWORD /d "1" /f >nul
Reg add "HKLM\System\Setup\MoSetup" /v "AllowUpgradesWithUnsupportedTPMOrCPU" /t REG_DWORD /d "1" /f >nul
rem Disable Inventory Collector
Reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d "1" /f >nul
rem Disable Windows Error Reporting
Reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f >nul
sc config WerSvc start=disabled >nul
sc config WecSvc start=disabled >nul
rem Disable Application Telemetry
Reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d "0" /f >nul
rem Disable the Customer Experience Improvement program (Below is 0 to disable)
Reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\SQM" /v "DisableCustomerImprovementProgram" /t REG_DWORD /d 0 /f >nul
Reg add "HKLM\Software\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f >nul
Reg add "HKLM\Software\Policies\Microsoft\AppV\CEIP" /v "CEIPEnable" /t REG_DWORD /d "0" /f >nul
Reg add "HKLM\Software\Policies\Microsoft\Messenger\Client" /v "CEIP" /t REG_DWORD /d "2" /f >nul
rem Disable Telemetry (Below is 1 to disable)
Reg add "HKLM\Software\Policies\Microsoft\MSDeploy\3" /v "EnableTelemetry" /t REG_DWORD /d "1" /f >nul
Reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >nul
Reg add "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >nul
Reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "MaxTelemetryAllowed" /t REG_DWORD /d "0" /f >nul
Reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "DisableTelemetryOptInChangeNotification" /t REG_DWORD /d "1" /f >nul
Reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "DisableTelemetryOptInSettingsUx" /t REG_DWORD /d "1" /f >nul
Reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "AllowCommercialDataPipeline" /t REG_DWORD /d 0 /f >nul
Reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "AllowDeviceNameInTelemetry" /t REG_DWORD /d 0 /f >nul
rem Disable Desktop Analytics
Reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "DisableEnterpriseAuthProxy" /t REG_DWORD /d 1 /f >nul
Reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "AllowDesktopAnalyticsProcessing" /t REG_DWORD /d 0 /f >nul
rem Disable Edge Telemetry
Reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "MicrosoftEdgeDataOptIn" /t REG_DWORD /d 0 /f >nul
rem Disable Diagnostics
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "ShowedToastAtLevel" /t REG_DWORD /d "1" /f >nul
Reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "DiagTrackAuthorization" /t REG_DWORD /d "775" /f >nul
Reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "DiagTrackStatus" /t REG_DWORD /d "2" /f >nul
Reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "UploadPermissionReceived" /t REG_DWORD /d "1" /f >nul
Reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\TraceManager" /v "MiniTraceSlotContentPermitted" /t REG_DWORD /d "1" /f >nul
Reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\TraceManager" /v "MiniTraceSlotEnabled" /t REG_DWORD /d "0" /f >nul
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "0" /f >nul
Reg add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v "disabletailoredexperiencesWithDiagnosticData" /t REG_DWORD /d "1" /f >nul
Reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "DisableDiagnosticDataViewer" /T REG_DWORD /d "1" /f >nul
sc config DiagTrack start=disabled >nul
sc config DiagSvc start=disabled >nul
rem Disable Text/Ink/Handwriting Telemetry
reg add "HKCU\Software\Microsoft\Input\TIPC" /v Enabled /t REG_DWORD /d 0 /f >nul
Reg add "HKLM\Software\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f >nul
Reg add "HKLM\Software\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f >nul
Reg add "HKLM\Software\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d "1" /f >nul
Reg add "HKLM\Software\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d "1" /f >nul
Reg add "HKCU\Software\Microsoft\Personalization\Settings" /v AcceptedPrivacyPolicy /t REG_DWORD /d "0" /f >nul
Reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\TextInput" /v "AllowLinguisticDataCollection" /t REG_DWORD /d "0" /f >nul
Reg add "HKCU\Software\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "0" /f >nul
Reg add "HKCU\Software\Microsoft\InputPersonalization\TrainedDataStore" /v "InsightsEnabled" /t REG_DWORD /d "0" /f >nul
rem Disable Advertising ID
Reg add "HKLM\Software\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d "1" /f >nul
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f >nul
REM Disable Tagged Energy Logging
Reg add "HKLM\System\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v "DisableTaggedEnergyLogging" /t REG_DWORD /d "1" /f >nul
Reg add "HKLM\System\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v "TelemetryMaxApplication" /t REG_DWORD /d "0" /f >nul
Reg add "HKLM\System\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v "TelemetryMaxTagPerApplication" /t REG_DWORD /d "0" /f >nul
rem Disable Automatic Installation of Suggested Windows 11 Apps
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" /f >nul
rem Disable Background Map Updates
Reg add "HKLM\Software\Policies\Microsoft\Windows\Maps" /v "AutoDownloadAndUpdateMapData" /t REG_DWORD /d "0" /f >nul
Reg add "HKLM\Software\Policies\Microsoft\Windows\Maps" /v "AllowUntriggeredNetworkTrafficOnSettingsPage" /t REG_DWORD /d "0" /f >nul
sc config MapsBroker start=disabled >nul
rem Disable Cortana
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d "0" /f >nul
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaConsent" /t REG_DWORD /d "0" /f >nul
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "AllowCortana" /t REG_DWORD /d "0" /f >nul
rem Disable Biometrics
Reg add "HKLM\Software\Policies\Microsoft\Biometrics" /v "Enabled" /t REG_DWORD /d "0" /f >nul
sc config WbioSrvc start=disabled >nul
rem Disable .NET CLI Telemetry
setx DOTNET_CLI_TELEMETRY_OPTOUT 1 >nul
rem Disable Powershell Telemetry
setx POWERSHELL_TELEMETRY_OPTOUT 1 >nul
rem Disable Diagnostic Tracing
call :ControlSet "Control\Diagnostics\Performance" "DisableDiagnosticTracing" "1" 2>nul
rem Disable Key Management System Telemetry
Reg add "HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v "NoGenTicket" /t REG_DWORD /d "1" /f >nul
rem Disable Usage Statistics
schtasks /change /tn "\Microsoft\Windows\Feedback\Siuf\DmClient" /disable >nul 2>&1
rem Block Telemetry IPs
cd %SystemRoot%\System32\drivers\etc
if not exist hosts.bak ren hosts hosts.bak >nul 2>&1
curl -l -s https://winhelp2002.mvps.org/hosts.txt -o hosts
if not exist hosts ren hosts.bak hosts >nul 2>&1
cd "%~dp0"
echo Disable Telemetry

::Harden Windows
rem Disable SMBv1 and SMBv2 as it's outdated and vulnerable to exploitation.
Reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "SMB1" /t REG_DWORD /d "0" /f >nul
Reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "SMB2" /t REG_DWORD /d "0" /f >nul
rem Block Anonymous Enumeration of SAM Accounts
rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220929
Reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "RestrictAnonymous" /t REG_DWORD /d "1" /f >nul
Reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "RestrictAnonymousSAM" /t REG_DWORD /d "1" /f >nul
rem Disable NetBios, can be exploited and is highly vulnerable.
call :ControlSet "Services\NetBT\Parameters\Interfaces" "NetbiosOptions" "2"
rem If NetBios manages to become enabled, protect against NBT-NS poisoning attacks
call :ControlSet "Services\NetBT\Parameters" "NodeType" "2"
rem Disable LanmanWorkstation
rem https://cyware.com/news/what-is-smb-vulnerability-and-how-it-was-exploited-to-launch-the-wannacry-ransomware-attack-c5a97c48
sc stop LanmanWorkstation >nul 2>&1
sc config LanmanWorkstation start=disabled >nul 2>&1
rem If LanmanWorkstation manages to become enabled, protect against other attacks
rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220932
Reg add "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" /v "RestrictNullSessAccess" /t REG_DWORD /d "1" /f >nul
rem Disable SMB Compression (Possible SMBGhost Vulnerability workaround)
Reg add "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" /v "DisableCompression" /t REG_DWORD /d "1" /f >nul
rem Harden lsass
Reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe" /v "AuditLevel" /t REG_DWORD /d "8" /f >nul
Reg add "HKLM\Software\Policies\Microsoft\Windows\CredentialsDelegation" /v "AllowProtectedCreds" /t REG_DWORD /d "1" /f >nul
Reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "DisableRestrictedAdminOutboundCreds" /t REG_DWORD /d "1" /f >nul
Reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "DisableRestrictedAdmin" /t REG_DWORD /d "0" /f >nul
Reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "RunAsPPL" /t REG_DWORD /d "1" /f >nul
Reg add "HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest" /v "Negotiate" /t REG_DWORD /d "0" /f >nul
Reg add "HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest" /v "UseLogonCredential" /t REG_DWORD /d "0" /f >nul
rem Delete defaultuser0
net user defaultuser0 /delete >nul 2>&1
rem Disable Remote Assistance
Reg add "HKLM\System\CurrentControlSet\Control\Remote Assistance" /v "fAllowFullControl" /t REG_DWORD /d "0" /f >nul
Reg add "HKLM\System\CurrentControlSet\Control\Remote Assistance" /v "fAllowToGetHelp" /t REG_DWORD /d "0" /f >nul
rem Set Strong Cryptography
Reg add "HKLM\Software\Microsoft\.NetFramework\v4.0.30319" /v "SchUseStrongCrypto" /t REG_DWORD /d "1" /f >nul
Reg add "HKLM\Software\WOW6432Node\Microsoft\.NETFramework\v4.0.30319" /v "SchUseStrongCrypto" /t REG_DWORD /d "1" /f >nul
rem Mitigate CVE-2022-30190
Reg delete HKEY_CLASSES_ROOT\ms-msdt /f >nul 2>&1
echo Harden Windows

::Enable xAPIC on Windows Servers
Reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion" /v "InstallationType" 2>nul | find /I "Server Core" >nul && (
bcdedit /set x2apicpolicy enable >nul
bcdedit /set uselegacyapicmode no >nul
echo Enable xAPIC
)

::SvcSplitThreshold
for /f "tokens=2 delims==" %%n in ('wmic os get TotalVisibleMemorySize /format:value') do set mem=%%n
call :ControlSet "Control" "SvcHostSplitThresholdInKB" "%mem%"
echo SvcSplitThreshold

::IOPageLockLimit
Reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "IOPageLockLimit" /t REG_DWORD /d "%mem%" /f >nul
echo IOPageLockLimit

::Increase Decommitting Memory Threshold
Reg add "HKLM\System\CurrentControlSet\Control\Session Manager" /v "HeapDeCommitFreeBlockThreshold" /t REG_DWORD /d "262144" /f >nul
echo Increase Decommitting Memory Threshold

::Enable PAE
bcdedit /set pae ForceEnable >nul
echo Enable PAE

::Disable Network Power Savings and Mitigations
powershell -NoProfile -NonInteractive -ExecutionPolicy Unrestricted -Command ^
$ErrorActionPreference = 'SilentlyContinue';^
Disable-NetAdapterPowerManagement -Name "*";^
Set-NetOffloadGlobalSetting -PacketCoalescingFilter Disabled -Chimney Disabled;^
Set-NetTCPSetting -SettingName "Internet" -MemoryPressureProtection Disabled
echo Disable Network Power Savings And Mitigations

::Enable Weak Host Model
for /f "tokens=1" %%a in ('netsh interface ip show interface ^| findstr /I "connected"') do (
netsh interface ipv6 set interface %%a weakhostreceive=enabled weakhostsend=enabled
netsh interface ipv4 set interface %%a weakhostreceive=enabled weakhostsend=enabled
) >nul
echo Enable Weak Host Model

::Disable Delivery Optimization
Reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings" /v "DownloadMode" /t REG_DWORD /d "0" /f >nul
echo Disable Delivery Optimization

::Set Congestion Provider To BBR2
netsh int tcp set global ecncapability=enabled >nul
for /f "tokens=7" %%a in ('netsh int tcp show supplemental ^| findstr /I "template"') do netsh int tcp set supplemental %%a CongestionProvider=bbr2 >nul
echo Set Congestion Provider To BBR2

::Disable Nagle's Algorithm
Reg add "HKLM\Software\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f >nul 2>&1  
for /f "tokens=3*" %%i in ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards" /f "ServiceName" /s ^|findstr /i /l "ServiceName"') do (
	Reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
	Reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TcpAckFrequency" /t REG_DWORD /d "1" /f
	Reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TcpDelAckTicks" /t REG_DWORD /d "0" /f
) >nul 2>&1
echo Disable Nagle's Algorithm

::Enable Winsock Autotuning
netsh winsock set autotuning on >nul
echo Enable Winsock Autotuning

::NIC
mkdir "%SYSTEMDRIVE%\Backup" 2>nul
for /f "tokens=2 delims==" %%n in ('wmic cpu get numberOfCores /format:value') do set CORES=%%n
for /f "tokens=3*" %%a in ('Reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\NetworkCards" /k /v /f "Description" /s /e ^| findstr /ri "REG_SZ"') do (
for /f %%g in ('Reg query "HKLM\System\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}" /s /f "%%b" /d ^| findstr /C:"HKEY"') do (
if not exist "%SYSTEMDRIVE%\Backup\(Default) %%b.reg" Reg export "%%g" "%SYSTEMDRIVE%\Backup\(Default) %%b.reg" /y
::Disable Wake Features
Reg add "%%g" /v "*WakeOnMagicPacket" /t REG_SZ /d "0" /f
Reg add "%%g" /v "*WakeOnPattern" /t REG_SZ /d "0" /f
Reg add "%%g" /v "WakeOnLink" /t REG_SZ /d "0" /f
Reg add "%%g" /v "S5WakeOnLan" /t REG_SZ /d "0" /f
Reg add "%%g" /v "WolShutdownLinkSpeed" /t REG_SZ /d "2" /f
Reg add "%%g" /v "*ModernStandbyWoLMagicPacket	" /t REG_SZ /d "0" /f
Reg add "%%g" /v "*DeviceSleepOnDisconnect" /t REG_SZ /d "0" /f
::Disable Power Saving Features
Reg add "%%g" /v "*NicAutoPowerSaver" /t REG_SZ /d "0" /f
Reg add "%%g" /v "*FlowControl" /t REG_SZ /d "0" /f
Reg add "%%g" /v "*EEE" /t REG_SZ /d "0" /f
Reg add "%%g" /v "EnablePME" /t REG_SZ /d "0" /f
Reg add "%%g" /v "EEELinkAdvertisement" /t REG_SZ /d "0" /f
Reg add "%%g" /v "ReduceSpeedOnPowerDown" /t REG_SZ /d "0" /f
Reg add "%%g" /v "PowerSavingMode" /t REG_SZ /d "0" /f
Reg add "%%g" /v "EnableGreenEthernet" /t REG_SZ /d "0" /f
Reg add "%%g" /v "ULPMode" /t REG_SZ /d "0" /f
Reg add "%%g" /v "GigaLite" /t REG_SZ /d "0" /f
Reg add "%%g" /v "EnableSavePowerNow" /t REG_SZ /d "0" /f
Reg add "%%g" /v "EnablePowerManagement" /t REG_SZ /d "0" /f
Reg add "%%g" /v "EnableDynamicPowerGating" /t REG_SZ /d "0" /f
Reg add "%%g" /v "EnableConnectedPowerGating" /t REG_SZ /d "0" /f
Reg add "%%g" /v "AutoPowerSaveModeEnabled" /t REG_SZ /d "0" /f
Reg add "%%g" /v "AutoDisableGigabit" /t REG_SZ /d "0" /f
Reg add "%%g" /v "AdvancedEEE" /t REG_SZ /d "0" /f
Reg add "%%g" /v "PowerDownPll" /t REG_SZ /d "0" /f
Reg add "%%g" /v "S5NicKeepOverrideMacAddrV2" /t REG_SZ /d "0" /f
Reg add "%%g" /v "MIMOPowerSaveMode" /t REG_SZ /d "3" /f
Reg add "%%g" /v "AlternateSemaphoreDelay" /t REG_SZ /d "0" /f
::Disable Interrupt Moderation
Reg add "%%g" /v "*interruptmoderation" /t REG_SZ /d "0" /f
::Disable JumboPacket
Reg add "%%g" /v "JumboPacket" /t REG_SZ /d "0" /f
::Interrupt Moderation Adaptive (Default)
Reg add "%%g" /v "ITR" /t REG_SZ /d "125" /f
::Receive/Transmit Buffers
Reg delete "%%g" /v "ReceiveBuffers" /f
Reg delete "%%g" /v "TransmitBuffers" /f
::Enable Throughput Booster
Reg add "%%g" /v "ThroughputBoosterEnabled" /t REG_SZ /d "1" /f
::PnPCapabilities
Reg add "%%g" /v "PnPCapabilities" /t REG_DWORD /d "24" /f
::Enable LargeSendOffloads
Reg add "%%g" /v "LsoV1IPv4" /t REG_SZ /d "1" /f
Reg add "%%g" /v "LsoV2IPv4" /t REG_SZ /d "1" /f
Reg add "%%g" /v "LsoV2IPv6" /t REG_SZ /d "1" /f
::Enable Offloads
Reg add "%%g" /v "TCPUDPChecksumOffloadIPv4" /t REG_SZ /d "3" /f
Reg add "%%g" /v "TCPUDPChecksumOffloadIPv6" /t REG_SZ /d "3" /f
Reg add "%%g" /v "UDPChecksumOffloadIPv4" /t REG_SZ /d "3" /f
Reg add "%%g" /v "UDPChecksumOffloadIPv6" /t REG_SZ /d "3" /f
Reg add "%%g" /v "TCPChecksumOffloadIPv4" /t REG_SZ /d "3" /f
Reg add "%%g" /v "TCPChecksumOffloadIPv6" /t REG_SZ /d "3" /f
Reg add "%%g" /v "IPChecksumOffloadIPv4" /t REG_SZ /d "3" /f
Reg add "%%g" /v "IPsecOffloadV1IPv4" /t REG_SZ /d "3" /f
Reg add "%%g" /v "IPsecOffloadV2" /t REG_SZ /d "3" /f
Reg add "%%g" /v "*IPsecOffloadV2IPv4" /t REG_SZ /d "3" /f
Reg add "%%g" /v "*PMARPOffload" /t REG_SZ /d "1" /f
Reg add "%%g" /v "*PMNSOffload" /t REG_SZ /d "1" /f
Reg add "%%g" /v "*PMWiFiRekeyOffload" /t REG_SZ /d "1" /f
::RSS
Reg add "%%g" /v "RSS" /t REG_SZ /d "1" /f
Reg add "%%g" /v "*NumRssQueues" /t REG_SZ /d "2" /f
if %CORES% geq 6 (
Reg add "%%g" /v "*RssBaseProcNumber" /t REG_SZ /d "4" /f
Reg add "%%g" /v "*RssMaxProcNumber" /t REG_SZ /d "5" /f
) else if %CORES% geq 4 (
Reg add "%%g" /v "*RssBaseProcNumber" /t REG_SZ /d "2" /f
Reg add "%%g" /v "*RssMaxProcNumber" /t REG_SZ /d "3" /f
) else (
Reg delete "%%g" /v "*RssBaseProcNumber" /f
Reg delete "%%g" /v "*RssMaxProcNumber" /f
)
) >nul 2>&1
)
echo Configure NIC

::Enable RSS
netsh int tcp set global rss=enabled >nul
echo Enable RSS

::Max Port Ranges
netsh int ipv4 set dynamicport udp start=1025 num=64511 >nul
netsh int ipv4 set dynamicport tcp start=1025 num=64511 >nul
echo Max Port Ranges

::Enable Network Task Offloading
Netsh int ip set global taskoffload=enabled >nul 2>&1
Reg add HKLM\System\CurrentControlSet\Services\TCPIP\Parameters /v DisableTaskOffload /t REG_DWORD /d 0 /f >nul
Reg add HKLM\System\CurrentControlSet\Services\Ipsec /v EnabledOffload /t REG_DWORD /d 1 /f >nul
echo Enable Network Task Offloading

::MMCSS
>"%tmp%\tmp.vbs" echo a = msgbox("CoutX detected that MMCSS has been disabled. Would you like to re-enable it?",vbYesNo+vbQuestion + vbSystemModal,"CoutX")
>>"%tmp%\tmp.vbs" echo if a = 6 then
>>"%tmp%\tmp.vbs" echo CreateObject("WScript.Shell").Run "Reg add HKLM\System\CurrentControlSet\Services\MMCSS /v Start /t REG_DWORD /d 2 /f", 0, True
>>"%tmp%\tmp.vbs" echo CreateObject("WScript.Shell").Run "sc config MMCSS start=auto", 0, True
>>"%tmp%\tmp.vbs" echo CreateObject("WScript.Shell").Run "sc start MMCSS", 0, True
>>"%tmp%\tmp.vbs" echo end if
sc query MMCSS | find "STOPPED" >nul && start "CoutX" wscript "%tmp%\tmp.vbs"
Reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Latency Sensitive" /t REG_SZ /d "True" /f >nul
Reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f >nul
Reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f >nul
Reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "8" /f >nul
echo Configure MMCSS

::Disable GPU Isolation
reg add "HKLM\System\CurrentControlSet\Control\GraphicsDrivers" /v "IOMMUFlags" /t REG_DWORD /d 0 /f >nul
echo Disable GPU Isolation

::Enable GPU MSI Mode
for /f %%a in ('wmic path Win32_VideoController get PNPDeviceID ^| find "PCI\VEN_"') do ^
reg query "HKLM\System\CurrentControlSet\Enum\%%a\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" >nul 2>&1 && (
call :ControlSet "Enum\%%a\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" "MSISupported" "1"
echo Enable GPU MSI Mode
)

::Background Apps
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f >nul
Reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsRunInBackground" /t REG_DWORD /d "2" /f >nul
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BackgroundAppGlobalToggle" /t REG_DWORD /d "0" /f >nul
echo Disable Background Apps

::Disable Hibernation
call :ControlSet "Control\Power" "HibernateEnabled" "0"
powercfg /h off >nul
echo Disable Hibernation

::Disable Sleep Study
schtasks /change /tn "\microsoft\windows\power efficiency diagnostics\analyzesystem" /disable >nul 2>&1
wevtutil set-log "Microsoft-Windows-SleepStudy/Diagnostic" /e:False >nul
wevtutil set-log "Microsoft-Windows-Kernel-Processor-Power/Diagnostic" /e:False >nul
wevtutil set-log "Microsoft-Windows-UserModePowerService/Diagnostic" /e:False >nul
echo Disable Sleep Study

::Adjust processor scheduling to allocate processor resources to programs
::2A Hex/42 Dec = Short, Fixed, High foreground boost.
Reg query "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" 2>nul | find "0x18" >nul && call :ControlSet "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" "Win32PrioritySeparation" "42"
Reg query "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" 2>nul | find "0x26" >nul && call :ControlSet "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" "Win32PrioritySeparation" "42"
echo W32PrioSep

::Raise the limit of paged pool memory
fsutil behavior set memoryusage 2 >nul
echo Raise The Limit of Paged Pool Memory

::https://www.serverbrain.org/solutions-2003/the-mft-zone-can-be-optimized.html
fsutil behavior set mftzone 2 >nul
echo Optimize The Mft Zone

::Enable Trim
fsutil behavior set disabledeletenotify 0 >nul
echo Enable Trim

::Disable Page File Encryption
fsutil behavior set encryptpagingfile 0 >nul
echo Disable Page File Encryption

::https://ttcshelbyville.wordpress.com/2018/12/02/should-you-disable-8dot3-for-performance-and-security/
fsutil behavior set disable8dot3 1 >nul
call :ControlSet "Control\FileSystem" "NtfsDisable8dot3NameCreation" "1"
echo Disable 8dot3

::Disable NTFS Compression
fsutil behavior set disablecompression 1 >nul
echo Disable NTFS Compression

wmic logicaldisk where "DriveType='3' and DeviceID='%systemdrive%'" get DeviceID 2>&1 | find "%systemdrive%" >nul && set "storageType=SSD" || set "storageType=HDD"
::Disable Last Access information on directories, performance/privacy
::https://www.tenforums.com/tutorials/139015-enable-disable-ntfs-last-access-time-stamp-updates-windows-10-a.html
if "%storageType%" equ "SSD" (fsutil behavior set disableLastAccess 0
call :ControlSet "Control\FileSystem" "NtfsDisableLastAccessUpdate" "2147483648") >nul
if "%storageType%" equ "HDD" (fsutil behavior set disableLastAccess 1
call :ControlSet "Control\FileSystem" "NtfsDisableLastAccessUpdate" "2147483649") >nul

::Opt out of nvidia telemetry
call :ControlSet "Services\NvTelemetryContainer" "Start" "4"
sc stop NvTelemetyContainer >nul
sc config NvTelemetyContainer start=disabled >nul
if exist "%systmedrive%\Program Files\NVIDIA Corporation\Installer2\InstallerCore\NVI2.DLL" (rundll32 "%systmedrive%\Program Files\NVIDIA Corporation\Installer2\InstallerCore\NVI2.DLL",UninstallPackage NvTelemetryContainer)
Reg add "HKLM\Software\NVIDIA Corporation\NvControlPanel2\Client" /v "OptInOrOutPreference" /t REG_DWORD /d 0 /f >nul
Reg add "HKLM\System\CurrentControlSet\Services\nvlddmkm\Global\Startup" /v "SendTelemetryData" /t REG_DWORD /d "0" /f >nul
Reg add "HKLM\Software\NVIDIA Corporation\Global\FTS" /v "EnableRID44231" /t REG_DWORD /d 0 /f >nul
Reg add "HKLM\Software\NVIDIA Corporation\Global\FTS" /v "EnableRID64640" /t REG_DWORD /d 0 /f >nul
Reg add "HKLM\Software\NVIDIA Corporation\Global\FTS" /v "EnableRID66610" /t REG_DWORD /d 0 /f >nul
Reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "NvBackend" /f >nul 2>&1
schtasks /change /disable /tn "NvTmRep_CrashReport1_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" >nul 2>&1
schtasks /change /disable /tn "NvTmRep_CrashReport2_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" >nul 2>&1
schtasks /change /disable /tn "NvTmRep_CrashReport3_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" >nul 2>&1
schtasks /change /disable /tn "NvTmRep_CrashReport4_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" >nul 2>&1
echo Disable Nvidia Telemetry

::Disable HDCP
for /f %%a in ('Reg query "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /t REG_SZ /s /e /f "NVIDIA" ^| findstr "HKEY"') do ^
if exist "C:\Program Files (x86)\Steam\steamapps\common\SteamVR" (
call :DelControlSet "%%a" "RMHdcpKeyglobZero"
echo Enable HDCP
) else if exist "C:/Program Files/Oculus/Software" (
call :DelControlSet "%%a" "RMHdcpKeyglobZero"
echo Enable HDCP
) else (
call :ControlSet "%%a" "RMHdcpKeyglobZero" "1"
echo Disable HDCP
)

::NVCP Settings
if "%GPU%" equ "NVIDIA" (
::GSync: Fullscreen And Windowed
call :NVCP "278196727" "2"
call :NVCP "294973784" "2"
echo Enable GSync for Fullscreen and Windowed Mode

::Enable Low Latency Mode
call :NVCP "390467" "1"
call :NVCP "277041152" "1"
echo Enable Low Latency Mode

::Texture Filtering Quality: Performance
call :NVCP "13510289" "10"
echo Set Texture Filtering Quality to Performance

::Enable ReBar
call :NVCP "983226" "1"
call :NVCP "983227" "1"
call :NVCP "983295" "AAAAQAAAAAA=" "Binary"
echo Enable ReBar

::Disable Ansel
call :NVCP "271965065" "0"
call :NVCP "276158834" "0"
echo Disable Ansel
)

::Disable HPET (Stock)
bcdedit /deletevalue useplatformclock >nul
echo Disable HPET

::Disable Synthetic Timers
bcdedit /set useplatformtick yes >nul
echo Disable Synthetic Timers

::Set power policy to Minimal Power Management
Reg.exe add "HKCU\Control Panel\PowerCfg\GlobalPowerPolicy" /v "Policies" /t REG_BINARY /d "01000000020000000100000000000000020000000000000000000000000000002c0100003232030304000000040000000000000000000000840300002c01000000000000840300000001646464640000" /f >nul
::Restore Power Settings
call :ControlSet "System\Services\NetBT\Parameters" "CsEnabled" "0"
call :ControlSet "System\Services\NetBT\Parameters" "PlatformAoAcOverride" "0"
::Import Ultimate Performance Power Plan
powercfg /duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb >nul 2>&1
powercfg /setactive bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb >nul
powercfg /delete eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee >nul 2>&1
powercfg /duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee >nul 2>&1
powercfg /setactive eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee >nul
powercfg /delete bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb >nul
::Disable Throttle States
powercfg -setacvalueindex scheme_current sub_processor THROTTLING 0 >nul
::Device Idle Policy: Performance
powercfg -setacvalueindex scheme_current sub_none DEVICEIDLE 0 >nul
::Interrupt Steering: Processor 1
echo %PROCESSOR_IDENTIFIER% | find /I "Intel" >nul && powercfg -setacvalueindex scheme_current SUB_INTSTEER MODE 6 >nul
::TDP Level High
call :ControlSet "Control\Power\PowerSettings\48df9d60-4f68-11dc-8314-0800200c9a66\07029cd8-4664-4698-95d8-43b2e9666596" "ACSettingIndex" "0"
::Hardware P-states
powercfg -setacvalueindex scheme_current sub_processor PERFAUTONOMOUS 1 >nul
powercfg -setacvalueindex scheme_current sub_processor PERFAUTONOMOUSWINDOW 1000 >nul
::Disable Hardware P-states Energy Saving
powercfg -setacvalueindex scheme_current sub_processor PERFEPP 0 >nul
::Enable Turbo Boost
powercfg -setacvalueindex scheme_current sub_processor PERFBOOSTMODE 1 >nul
powercfg -setacvalueindex scheme_current sub_processor PERFBOOSTPOL 100 >nul
::Disable Sleep States
powercfg -setacvalueindex scheme_current SUB_SLEEP AWAYMODE 0 >nul
powercfg -setacvalueindex scheme_current SUB_SLEEP ALLOWSTANDBY 0 >nul
powercfg -setacvalueindex scheme_current SUB_SLEEP HYBRIDSLEEP 0 >nul
powercfg -setacvalueindex scheme_current SUB_SLEEP UNATTENDSLEEP 0 >nul
powercfg -setacvalueindex scheme_current SUB_IR DEEPSLEEP 0 >nul
::Disable Core Parking
echo %PROCESSOR_IDENTIFIER% | find /I "Intel" >nul && (
powercfg -setacvalueindex scheme_current sub_processor CPMINCORES 100 >nul
) || (
powercfg -setacvalueindex scheme_current SUB_INTSTEER UNPARKTIME 0 >nul
powercfg -setacvalueindex scheme_current SUB_INTSTEER PERPROCLOAD 10000 >nul
)
::Disable Frequency Scaling
powercfg -setacvalueindex scheme_current sub_processor PROCTHROTTLEMIN 100 >nul
::Prefer Performant Processors
powercfg -setacvalueindex scheme_current sub_processor SHORTSCHEDPOLICY 2 >nul
powercfg -setacvalueindex scheme_current sub_processor SCHEDPOLICY 2 >nul
::Don't turn off display when plugged in
powercfg /change standby-timeout-ac 0
powercfg /change monitor-timeout-ac 0
powercfg /change hibernate-timeout-ac 0
::Apply Changes
powercfg -setactive scheme_current >nul
powercfg -changename scheme_current "CoutX Ultimate Performance" "For CoutX Optimizer %version% (dsc.gg/CoutX) By UnLovedCookie" >nul
echo CoutX Power Plan

:::::::::::::::::::::::::::::::::
:::::::::::::::::::::::::::::::::
::::Disable Device Throttling::::
:::::::::::::::::::::::::::::::::
:::::::::::::::::::::::::::::::::

Reg query HKCU\Software\CoutX /v DisableDeviceThrottling 2>nul | find "0x1" >nul && (

	::Disable NVMe Power Saving
	rem NVMe Power State Transition Latency Tolerance: 0
	powercfg -setacvalueindex scheme_current SUB_DISK dbc9e238-6de9-49e3-92cd-8c2b4946b472 0 >nul
	powercfg -setacvalueindex scheme_current SUB_DISK fc95af4d-40e7-4b6d-835a-56d131dbc80e 0 >nul
	rem Disable NVMe Idle Timeout
	powercfg /setacvalueindex scheme_current SUB_DISK d3d55efd-c1ff-424e-9dc3-441be7833010 0 >nul
	powercfg /setacvalueindex scheme_current SUB_DISK d639518a-e56d-4345-8af2-b9f32fb26109 0 >nul
	rem NVME NOPPME: ON
	powercfg /setacvalueindex scheme_current SUB_DISK DISKNVMENOPPME 1 >nul
	echo Disable NVMe Power Saving
	
	::Disable USB Power Savings
	for /f "tokens=*" %%a in ('Reg query "HKLM\System\CurrentControlSet\Enum" /s /f "StorPort" 2^>nul ^| findstr "StorPort"') do call :ControlSet "%%a" "EnableIdlePowerManagement" "0"
	for /f %%a in ('wmic PATH Win32_PnPEntity GET DeviceID ^| find "USB\VID_"') do (
	call :ControlSet "Enum\%%a\Device Parameters" "EnhancedPowerManagementEnabled" "0"
	call :ControlSet "Enum\%%a\Device Parameters" "AllowIdleIrpInD3" "0"
	call :ControlSet "Enum\%%a\Device Parameters" "EnableSelectiveSuspend" "0"
	call :ControlSet "Enum\%%a\Device Parameters" "DeviceSelectiveSuspended" "0"
	call :ControlSet "Enum\%%a\Device Parameters" "SelectiveSuspendEnabled" "0"
	call :ControlSet "Enum\%%a\Device Parameters" "SelectiveSuspendOn" "0"
	call :ControlSet "Enum\%%a\Device Parameters" "D3ColdSupported" "0"
	)
	echo Disable USB Power Savings
	
	::Disable Selective USB Suspension
	powercfg -setacvalueindex scheme_current 2a737441-1930-4402-8d77-b2bebba308a3 d4e98f31-5ffe-4ce1-be31-1b38b384c009 0 >nul
	powercfg -setacvalueindex scheme_current 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0 >nul
	powercfg -setacvalueindex scheme_current 2a737441-1930-4402-8d77-b2bebba308a3 0853a681-27c8-4100-a2fd-82013e970683 0 >nul
	echo Disable Selective USB Suspension
	
	::Disable Link State Power Management
	powercfg -setacvalueindex scheme_current SUB_PCIEXPRESS ASPM 0 >nul
	rem Disable AHCI Link Power Management
	powercfg -setacvalueindex scheme_current SUB_DISK 0b2d69d7-a2a1-449c-9680-f91c70521c60 0 >nul
	powercfg -setacvalueindex scheme_current SUB_DISK dab60367-53fe-4fbc-825e-521d069d2456 0 >nul
	echo Disable Link State Power Management

	::Disable Storage Device Idle
	Reg add "HKLM\System\CurrentControlSet\Services\stornvme\Parameters\Device" /v "IdlePowerMode" /t REG_DWORD /d "0" /f >nul
	echo Disable Storage Device Idle
	
	::Apply Power Plan Changes
	powercfg -setactive scheme_current >nul
	
	 Reg add HKCU\Software\CoutX /v DisableDeviceThrottlingRan /t REG_DWORD /d 1 /f >nul
) || Reg query HKCU\Software\CoutX /v DisableDeviceThrottlingRan 2>nul | find "0x1" >nul && (

	::Reset USB Power Savings
	for /f "tokens=*" %%a in ('Reg query "HKLM\System\CurrentControlSet\Enum" /s /f "StorPort" 2^>nul ^| findstr "StorPort"') do call :ControlSet "%%a" "EnableIdlePowerManagement" "0"
	for /f %%a in ('wmic PATH Win32_PnPEntity GET DeviceID ^| find "USB\VID_"') do (
	call :DelControlSet "Enum\%%a\Device Parameters" "EnhancedPowerManagementEnabled"
	call :DelControlSet "Enum\%%a\Device Parameters" "AllowIdleIrpInD3"
	call :DelControlSet "Enum\%%a\Device Parameters" "EnableSelectiveSuspend"
	call :DelControlSet "Enum\%%a\Device Parameters" "DeviceSelectiveSuspended"
	call :DelControlSet "Enum\%%a\Device Parameters" "SelectiveSuspendEnabled"
	call :DelControlSet "Enum\%%a\Device Parameters" "SelectiveSuspendOn"
	call :DelControlSet "Enum\%%a\Device Parameters" "D3ColdSupported"
	)
	echo Disable USB Power Savings
	
	::Reset Storage Device Idle
	Reg delete "HKLM\System\CurrentControlSet\Services\stornvme\Parameters\Device" /v "IdlePowerMode" /f >nul
	echo Disable Storage Device Idle

	 Reg delete HKCU\Software\CoutX /v DisableDeviceThrottlingRan /f >nul
)

:::::::::::::::::::::::::::
:::::::::::::::::::::::::::
::::Disable Mitigations::::
:::::::::::::::::::::::::::
:::::::::::::::::::::::::::

Reg query HKCU\Software\CoutX /v DisableMitigations 2>nul | find "0x1" >nul && (
	::Disable Kernel Mitigations
	for /f "tokens=3 skip=2" %%i in ('Reg query "HKLM\System\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationAuditOptions"') do set mitigation_mask=%%i
	for /l %%i in (0,1,9) do set mitigation_mask=!mitigation_mask:%%i=2!
	Reg add "HKLM\System\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationOptions" /t REG_BINARY /d "!mitigation_mask!" /f >nul
	Reg add "HKLM\System\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationAuditOptions" /t REG_BINARY /d "!mitigation_mask!" /f >nul
	::Disable More Kernel Mitigations (Enforced Intel SGX causes boot crashes/loops)
	echo %PROCESSOR_IDENTIFIER% | find /I "Intel" >nul || bcdedit /set allowedinmemorysettings 0x0 >nul
	echo Disable Kernel Mitigations
	
	::Disable CSRSS mitigations
	Reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe" /v MitigationAuditOptions /t REG_BINARY /d "!mitigation_mask!" /f >nul
	Reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe" /v MitigationOptions /t REG_BINARY /d "!mitigation_mask!" /f >nul
	echo Disable CSRSS mitigations
	
	::Disable Process Mitigations
	PowerShell -nop "ForEach($v in (Get-Command -Name \"Set-ProcessMitigation\").Parameters[\"Disable\"].Attributes.ValidValues){Set-ProcessMitigation -System -Disable $v.ToString() -ErrorAction SilentlyContinue}" >nul
	echo Disable Process Mitigations
	
	::Disable TsX
	call :ControlSet "Control\Session Manager\kernel" "DisableTsx" "1"
	echo Disable TsX
	
	::Disable VSM
	bcdedit /set vm No >nul
	bcdedit /set vsmlaunchtype Off >nul
	bcdedit /set hypervisorlaunchtype off >nul
	echo Disable VSM
	
	::Disable VBS
	call :ControlSet "Control\DeviceGuard" "EnableVirtualizationBasedSecurity" "0"
	bcdedit /set loadoptions "DISABLE-LSA-ISO,DISABLE-VBS" >nul
	bcdedit /set isolatedcontext No >nul
	echo Disable VBS
	
	::Disable Memory Integrity
	call :ControlSet "Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" "Enabled" "0"
	call :ControlSet "Control\DeviceGuard" "HypervisorEnforcedCodeIntegrity" "0"
	echo Disable Memory Integrity

	::Disable Data Execution Prevention
	echo %PROCESSOR_IDENTIFIER% | find /I "Intel" >nul && (
	bcdedit /set nx AlwaysOff >nul
	Reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Main" /v "DEPOff" /t REG_DWORD /d 1 /f >nul
	Reg add "HKLM\Software\Policies\Microsoft\Windows\Explorer" /v "NoDataExecutionPrevention" /t REG_DWORD /d 1 /f >nul
	Reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "DisableHHDEP" /t REG_DWORD /d 1 /f >nul
	)
	echo Disable Data Execution Prevention
	
	::Disable Dma Memory Protection
	Reg add "HKLM\Software\Microsoft\PolicyManager\default\DmaGuard\DeviceEnumerationPolicy" /v "value" /t REG_DWORD /d "2" /f >nul
	Reg add "HKLM\Software\Policies\Microsoft\FVE" /v "DisableExternalDMAUnderLock" /t REG_DWORD /d "0" /f >nul
	Reg add "HKLM\Software\Policies\Microsoft\Windows\DeviceGuard" /v "HVCIMATRequired" /t REG_DWORD /d "0" /f >nul
	echo Disable Dma Remapping / Memory Protection
	
	::Disable SEHOP
	call :ControlSet "Control\Session Manager\kernel" "DisableExceptionChainValidation" "1"
	call :ControlSet "Control\Session Manager\kernel" "KernelSEHOPEnabled" "0"
	echo Disable SEHOP
	
	::Disable File System Mitigations
	call :ControlSet "Control\Session Manager" "ProtectionMode" "0"
	
	::Disable Control Flow Guard
	call :ControlSet "Control\Session Manager\Memory Management" "EnableCfg" "0"
	echo Disable Control Flow Guard
	
	::Disable Spectre And Meltdown
	call :ControlSet "Control\Session Manager\Memory Management" "FeatureSettings" "3"
	call :ControlSet "Control\Session Manager\Memory Management" "FeatureSettingsOverride" "3"
	call :ControlSet "Control\Session Manager\Memory Management" "FeatureSettingsOverrideMask" "3"
	rem Disabling Microcode Mitigations on Windows 24H2 Causes BSOD
	for /f "tokens=4-9 delims=. " %%i in ('ver') do if %%k lss 25967 (
		takeown /f "C:\Windows\System32\mcupdate_GenuineIntel.dll" /r /d y >nul 2>&1
		takeown /f "C:\Windows\System32\mcupdate_AuthenticAMD.dll" /r /d y >nul 2>&1
		ren %WinDir%\System32\mcupdate_GenuineIntel.dll mcupdate_GenuineIntel.dll.old 2>nul
		ren %WinDir%\System32\mcupdate_AuthenticAMD.dll mcupdate_AuthenticAMD.dll.old 2>nul
	)
	echo Disable Spectre And Meltdown
	
	::Disable ITLB Multi-hit mitigations
	Reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Virtualization" /v "IfuErrataMitigations" /t REG_DWORD /d "0" /f >nul
	echo Disable ITLB Multi-hit mitigations
	
	::Disable FTH
	Reg add HKLM\Software\Microsoft\FTH /v Enabled /t REG_DWORD /d 0 /f >nul
	rundll32.exe fthsvc.dll,FthSysprepSpecialize
	echo Disable FTH
	
	 Reg add HKCU\Software\CoutX /v DisableMitigationsgRan /t REG_DWORD /d 1 /f >nul
) || Reg query HKCU\Software\CoutX /v DisableMitigationsgRan 2>nul | find "0x1" >nul && (
	::Reset Kernel Mitigations
	Reg delete "HKLM\System\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationOptions" /f >nul 2>&1
	Reg delete "HKLM\System\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationAuditOptions" /f >nul 2>&1
	::Reset More Kernel Mitigations
	bcdedit /deletevalue allowedinmemorysettings >nul
	
	::Reset CSRSS mitigations
	Reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe" /v MitigationAuditOptions /f >nul 2>&1
	Reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe" /v MitigationOptions /f >nul 2>&1
	
	::Reset System Mitigations
	PowerShell -nop "Set-ProcessMitigation -System -Reset" >nul 2>&1
	
	::Reset TsX
	call :DelControlSet "Control\Session Manager\kernel" "DisableTsx"
	
	::Reset VSM
	bcdedit /deletevalue vm >nul
	bcdedit /deletevalue vsmlaunchtype >nul
	bcdedit /deletevalue hypervisorlaunchtype >nul
	
	::Reset VBS
	call :DelControlSet "Control\DeviceGuard" "EnableVirtualizationBasedSecurity"
	bcdedit /deletevalue loadoptions >nul
	bcdedit /deletevalue isolatedcontext >nul
	
	::Reset Memory Integrity
	call :DelControlSet "Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" "Enabled"
	call :DelControlSet "Control\DeviceGuard" "HypervisorEnforcedCodeIntegrity"
	
	::Reset Data Execution Prevention
	bcdedit /deletevalue nx >nul
	Reg delete "HKLM\Software\Policies\Microsoft\Internet Explorer\Main" /v "DEPOff" /f >nul 2>&1
	Reg delete "HKLM\Software\Policies\Microsoft\Windows\Explorer" /v "NoDataExecutionPrevention" /f >nul 2>&1
	Reg delete "HKLM\Software\Policies\Microsoft\Windows\System" /v "DisableHHDEP" /f >nul 2>&1
	
	::Reset Dma Memory Protection
	Reg delete "HKLM\Software\Microsoft\PolicyManager\default\DmaGuard\DeviceEnumerationPolicy" /v "value" /f >nul 2>&1
	Reg delete "HKLM\Software\Policies\Microsoft\FVE" /v "DisableExternalDMAUnderLock" /f >nul 2>&1
	Reg delete "HKLM\Software\Policies\Microsoft\Windows\DeviceGuard" /v "HVCIMATRequired" /f >nul 2>&1
	
	::Reset SEHOP
	call :DelControlSet "Control\Session Manager\kernel" "DisableExceptionChainValidation" "1"
	call :DelControlSet "Control\Session Manager\kernel" "KernelSEHOPEnabled" "0"
	
	::Reset File System Mitigations
	call :DelControlSet "Control\Session Manager" "ProtectionMode"
	
	::Reset Control Flow Guard
	call :DelControlSet "Control\Session Manager\Memory Management" "EnableCfg"
	
	::Reset Spectre And Meltdown
	call :DelControlSet "Control\Session Manager\Memory Management" "FeatureSettings"
	call :DelControlSet "Control\Session Manager\Memory Management" "FeatureSettingsOverride"
	call :DelControlSet "Control\Session Manager\Memory Management" "FeatureSettingsOverrideMask"
	takeown /f "C:\Windows\System32\mcupdate_GenuineIntel.dll.old" /r /d y >nul 2>&1
	takeown /f "C:\Windows\System32\mcupdate_AuthenticAMD.dll.old" /r /d y >nul 2>&1
	ren %WinDir%\System32\mcupdate_GenuineIntel.dll.old mcupdate_GenuineIntel.dll
	ren %WinDir%\System32\mcupdate_AuthenticAMD.dll.old mcupdate_AuthenticAMD.dll
	echo Reset Mitigations
	
	::Reset ITLB Multi-hit mitigations
	Reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Virtualization" /v "IfuErrataMitigations" /t REG_DWORD /d "0" /f >nul
	echo Reset ITLB Multi-hit mitigations
	
	::Reset FTH
	Reg delete HKLM\Software\Microsoft\FTH /v Enabled /f >nul
	rundll32.exe fthsvc.dll,FthSysprepSpecialize
	echo Reset FTH
	
	Reg delete HKCU\Software\CoutX /v DisableMitigationsgRan /f >nul
)

::::::::::::::::::::::::::::::::::::
::::::::::::::::::::::::::::::::::::
::::Disable GPU Power Throttling::::
::::::::::::::::::::::::::::::::::::
::::::::::::::::::::::::::::::::::::

Reg query HKCU\Software\CoutX /v DisableGPUThrottling 2>nul | find "0x1" >nul && (
	if "%GPU%" equ "NVIDIA" (
		::Disable Forced P2 State
		call :NVCP "1343646814" "0"
		echo Disable Forced P2 State
		::Prefer Maximum Performance
		call :NVCP "274197361" "1"
		echo Prefer Maximum Performance
	)

	::Disable GpuEnergyDrv
	call :ControlSet "Services\GpuEnergyDrv" "Start" "4"
	echo Disable GpuEnergyDrv
	::Grab Nvidia Graphics Card Registry Key
	for /f %%a in ('Reg query "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /t REG_SZ /s /e /f "NVIDIA" ^| findstr "HKEY"') do (
	::Disable Dynamic PStates
	reg query "%%a" /v "DisableDynamicPState" >nul 2>&1 && (
	Call :ControlSet "%%a" "DisableDynamicPState" "1"
	echo Disable Dynamic PStates
	)
	::Enable KBoost
	Call :ControlSet "%%a" "PowerMizerEnable" "1"
	Call :ControlSet "%%a" "PowerMizerLevel" "1"
	Call :ControlSet "%%a" "PowerMizerLevelAC" "1"
	Call :ControlSet "%%a" "PerfLevelSrc" "8755"
	echo Enable KBoost
	::Disable Overheat Slowdown
	Call :ControlSet "%%a" "EnableCoreSlowdown" "0"
	Call :ControlSet "%%a" "EnableMClkSlowdown" "0"
	Call :ControlSet "%%a" "EnableNVClkSlowdown" "0"
	echo Disable Overheat Slowdown
	)

	::Grab iGPU Registry Key
	for /f %%i in ('Reg query "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /t REG_SZ /s /e /f "Intel" ^| findstr "HKEY"') do (
	::Disable iGPU CStates
	reg query "%%i" /v "AllowDeepCStates" >nul 2>&1 && (
	Call :ControlSet "%%i" "AllowDeepCStates" "0"
	echo Disable iGPU CStates
	)
	::Intel iGPU Settings
	Call :ControlSet "%%i" "Disable_OverlayDSQualityEnhancement" "1"
	Call :ControlSet "%%i" "IncreaseFixedSegment" "1"
	Call :ControlSet "%%i" "AdaptiveVsyncEnable" "0"
	Call :ControlSet "%%i" "DisablePFonDP" "1"
	Call :ControlSet "%%i" "EnableCompensationForDVI" "1"
	Call :ControlSet "%%i" "NoFastLinkTrainingForeDP" "0"
	Call :ControlSet "%%i" "ACPowerPolicyVersion" "16898"
	Call :ControlSet "%%i" "DCPowerPolicyVersion" "16642"
	echo Intel iGPU Settings
	)
	
	 Reg add HKCU\Software\CoutX /v DisableGPUThrottlingRan /t REG_DWORD /d 1 /f >nul
) || Reg query HKCU\Software\CoutX /v DisableGPUThrottlingRan 2>nul | find "0x1" >nul && (
	::Prefer Optimal Performance
	call :NVCP "274197361" "5"
	echo Reset NVCP Settings
	
	::Enable GpuEnergyDrv
	call :ControlSet "Services\GpuEnergyDrv" "Start" "2"
	echo Enable GpuEnergyDrv

	for /f %%a in ('Reg query "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /t REG_SZ /s /e /f "NVIDIA" ^| findstr "HKEY"') do (
	reg query "%%a" /v "DisableDynamicPState" >nul 2>&1 && (
	Call :ControlSet "%%a" "DisableDynamicPState" "0"
	echo Enable Dynamic PStates
	)
	Call :DelControlSet "%%a" "PowerMizerEnable"
	Call :DelControlSet "%%a" "PowerMizerLevel"
	Call :DelControlSet "%%a" "PowerMizerLevelAC"
	Call :DelControlSet "%%a" "PerfLevelSrc"
	echo Disable KBoost
	Call :DelControlSet "%%a" "EnableCoreSlowdown"
	Call :DelControlSet "%%a" "EnableMClkSlowdown"
	Call :DelControlSet "%%a" "EnableNVClkSlowdown"
	echo Enable Overheat Slowdown
	)
	
	::Grab iGPU Registry Key
	for /f %%i in ('Reg query "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /t REG_SZ /s /e /f "Intel" ^| findstr "HKEY"') do (
	::Reset iGPU CStates
	reg query "%%i" /v "AllowDeepCStates" >nul 2>&1 && (
	Call :ControlSet "%%i" "AllowDeepCStates" "1"
	echo Enable iGPU CStates
	)
	)
	Reg delete HKCU\Software\CoutX /v DisableGPUThrottlingRan /f >nul
)

::::::::::::::::::::::::::::::::::::
::::::::::::::::::::::::::::::::::::
::::Disable CPU Power Throttling::::
::::::::::::::::::::::::::::::::::::
::::::::::::::::::::::::::::::::::::

::QoS Packet Scheduler
>"%tmp%\tmp.vbs" echo a = msgbox("CoutX detected that the QoS Packet Scheduler has been disabled. Would you like to re-enable it?",vbYesNo+vbQuestion + vbSystemModal,"CoutX")
>>"%tmp%\tmp.vbs" echo if a = 6 then
>>"%tmp%\tmp.vbs" echo CreateObject("WScript.Shell").Run "Reg add HKLM\System\CurrentControlSet\Services\Psched /v Start /t REG_DWORD /d 2 /f", 0, True
>>"%tmp%\tmp.vbs" echo CreateObject("WScript.Shell").Run "sc config Psched start=auto", 0, True
>>"%tmp%\tmp.vbs" echo CreateObject("WScript.Shell").Run "sc start Psched", 0, True
>>"%tmp%\tmp.vbs" echo end if

Reg query HKCU\Software\CoutX /v DisableCPUThrottling 2>nul | find "0x1" >nul && (
	::Configure C-States
	powercfg -setacvalueindex scheme_current sub_processor IDLEPROMOTE 100 >nul
	powercfg -setacvalueindex scheme_current sub_processor IDLEDEMOTE 100 >nul
	powercfg -setacvalueindex scheme_current sub_processor IDLECHECK 100000 >nul
	powercfg -setacvalueindex scheme_current sub_processor IDLESCALING 0 >nul
	::Apply Changes
	powercfg -setactive scheme_current >nul
	echo Configure C-States
	
	::Disable Dynamic Tick
	bcdedit /set disabledynamictick yes >nul
	echo Disable Dynamic Tick

	::Timer Resolution
	Call :ControlSet "Control\Session Manager\kernel" "GlobalTimerResolutionRequests" "1"
	taskkill /f /im SetTimerResolution.exe >nul 2>&1
	Copy /Y SetTimerResolution.exe %systemdrive%\SetTimerResolution.exe >nul 2>&1
	%systemdrive%\SetTimerResolution.exe -Install >nul 2>&1
	net start STR >nul 2>&1
	echo Timer Resolution
	
	::Set QoS TimerResolution
	sc query Psched | find "STOPPED" >nul && start "CoutX" wscript "%tmp%\tmp.vbs"
	::Enable QoS Policy outside domain networks
	Reg add "HKLM\System\CurrentControlSet\Services\Tcpip\QoS" /v "Do not use NLA" /t REG_DWORD /d "1" /f >nul 2>&1
	::QoS Timer Resolution
	Reg add "HKLM\Software\Policies\Microsoft\Windows\Psched" /v "TimerResolution" /t REG_DWORD /d "1" /f >nul 2>&1
	echo QoS TimerResolution
	
	::Disable The Processor Power Management Driver
	call :ControlSet "Services\IntelPPM" "Start" "4"
	call :ControlSet "Services\AmdPPM" "Start" "4"
	echo Disable The Processor Power Management Driver
	
	 Reg add HKCU\Software\CoutX /v DisableCPUThrottlingRan /t REG_DWORD /d 1 /f >nul
) || Reg query HKCU\Software\CoutX /v DisableCPUThrottlingRan 2>nul | find "0x1" >nul && (
	::Reset Dynamic Tick
	bcdedit /deletevalue disabledynamictick >nul
	echo Reset Dynamic Tick

	::Timer Resolution
	net stop STR >nul 2>&1
	%systemdrive%\SetTimerResolution.exe -Uninstall >nul 2>&1
	del /f "%systemdrive%\SetTimerResolution.exe" 2>nul
	echo Reset Timer Resolution
	
	::QoS Timer Resolution
	Reg delete "HKLM\Software\Policies\Microsoft\Windows\Psched" /v "TimerResolution" /f >nul 2>&1
	::Reset QoS Timer Resolution
	Reg delete "HKLM\Software\Policies\Microsoft\Windows\Psched" /v "TimerResolution" /f >nul 2>&1
	echo Reset QoS TimerResolution

	::Enable The Processor Power Management Driver
	call :ControlSet "Services\IntelPPM" "Start" "2"
	call :ControlSet "Services\AmdPPM" "Start" "2"
	echo Enable The Processor Power Management Driver

	Reg delete HKCU\Software\CoutX /v DisableCPUThrottlingRan /f >nul
)

::::::::::::::::::::
::::::::::::::::::::
::::Experimental::::
::::::::::::::::::::
::::::::::::::::::::

Reg query HKCU\Software\CoutX /v ExTweaks 2>nul | find "0x1" >nul && (
	::Disable Memory Compression and Page Combining
	call :ControlSet "Control\Session Manager\Memory Management" "DisablePageCombining" "1"
	powershell -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Unrestricted -Command "Disable-MMAgent -mc -pc"
	echo Disable Memory Compression and Page Combining

	::Disable Paging Executive
	call :ControlSet "Control\Session Manager\Memory Management" "DisablePagingExecutive" "1"
	echo Disable Paging Executive

	::Disable Large System Cache
	call :ControlSet "Control\Session Manager\Memory Management" "LargeSystemCache" "1"
	echo Disable Large System Cache

	::Disable Prefetch
	sc stop "SysMain" & sc config "SysMain" start=disabled
	call :ControlSet "Control\Session Manager\Memory Management\PrefetchParameters" "EnablePrefetcher" "0"
	call :ControlSet "Control\Session Manager\Memory Management\PrefetchParameters" "EnableSuperfetch" "0"
	call :ControlSet "Control\Session Manager\Memory Management\PrefetchParameters" "EnableBoottrace" "0"
	call :ControlSet "Control\Session Manager\Memory Management\PrefetchParameters" "SfTracingState" "0"
	echo Disable Prefetch

	::Disable Preemption
	call :ControlSet "Control\GraphicsDrivers\Scheduler" "EnablePreemption" "0"
	echo Disable Preemption
	
	 Reg add HKCU\Software\CoutX /v ExTweaksRan /t REG_DWORD /d 1 /f >nul
) || Reg query HKCU\Software\CoutX /v ExTweaksRan 2>nul | find "0x1" >nul && (
	sc config "SysMain" start=auto & sc start "SysMain"
	call :DelControlSet "Control\Session Manager\Memory Management" "DisablePagingExecutive"
	call :DelControlSet "Control\Session Manager\Memory Management" "DisablePageCombining"
	call :DelControlSet "Control\Session Manager\Memory Management" "LargeSystemCache"
	call :DelControlSet "Control\Session Manager\Memory Management\PrefetchParameters" "EnablePrefetcher"
	call :DelControlSet "Control\Session Manager\Memory Management\PrefetchParameters" "EnableSuperfetch"
	call :DelControlSet "Control\Session Manager\Memory Management\PrefetchParameters" "EnableBoottrace"
	call :DelControlSet "Control\Session Manager\Memory Management\PrefetchParameters" "SfTracingState"
	call :DelControlSet "Control\GraphicsDrivers\Scheduler" "EnablePreemption"
	Reg delete HKCU\Software\CoutX /v ExTweaksRan /f >nul
)

::Apply Nvidia Profile
call :NVCP "End"
if "%GPU%" equ "NVIDIA" start "" /D "nvidiaProfileInspector" nvidiaProfileInspector.exe CoutXProfile.nip
echo Apply Nvidia Profile

::Flush DNS
ipconfig /flushdns >nul
::Restart Explorer
(taskkill /f /im explorer.exe && start explorer.exe) >nul
::End
taskkill /f /im regedit.exe >nul 2>&1
taskkill /f /im MinSudo.exe >nul 2>&1
taskkill /f /im fsutil.exe >nul 2>&1
exit 0

::Restart Graphics Driver
devmanview /disable_enable "NVIDIA GeForce GTX 970"

:ControlSet
set ControlSet=%1
if %ControlSet% neq %ControlSet:CurrentControlSet=% (
	Reg query !ControlSet! /v %2 >nul 2>&1 && (
		Reg query "HKLM\System\ControlSet003" /v %2 >nul 2>&1 || (
			echo hi >nul
		)
	)
	Reg add !ControlSet! /v %2 /t REG_DWORD /d %3 /f >nul
	Reg add !ControlSet:CurrentControlSet=ControlSet001! /v %2 /t REG_DWORD /d %3 /f >nul
	Reg add !ControlSet:CurrentControlSet=ControlSet002! /v %2 /t REG_DWORD /d %3 /f >nul
) else (
Reg add "HKLM\System\CurrentControlSet\%~1" /v %2 /t REG_DWORD /d %3 /f >nul
Reg add "HKLM\System\ControlSet001\%~1" /v %2 /t REG_DWORD /d %3 /f >nul
Reg add "HKLM\System\ControlSet002\%~1" /v %2 /t REG_DWORD /d %3 /f >nul
)
goto:EOF

:DelControlSet
set ControlSet=%1
if %ControlSet% neq %ControlSet:CurrentControlSet=% (
Reg delete !ControlSet! /v "%~2" /f >nul 2>&1
Reg delete !ControlSet:CurrentControlSet=ControlSet001! /v "%~2" /f >nul 2>&1
Reg delete !ControlSet:CurrentControlSet=ControlSet002! /v "%~2" /f >nul 2>&1
) else (
Reg delete "HKLM\System\CurrentControlSet\%~1" /v "%~2" /f >nul 2>&1
Reg delete "HKLM\System\ControlSet001\%~1" /v "%~2" /f >nul 2>&1
Reg delete "HKLM\System\ControlSet002\%~1" /v "%~2" /f >nul 2>&1
)
goto:EOF

:NVCP

if not exist "nvidiaProfileInspector\CoutXProfile.nip" (
echo ^<?xml version="1.0" encoding="utf-16"?^> > "nvidiaProfileInspector\CoutXProfile.nip"
for %%a in (
"<ArrayOfProfile>"
"  <Profile>"
"    <ProfileName>Base Profile</ProfileName>"
"    <Executeables />"
"    <Settings>"
) do (echo %%~a) >> "nvidiaProfileInspector\CoutXProfile.nip"
)

if "%~1" equ "End" (
for %%a in (
"    </Settings>"
"  </Profile>"
"</ArrayOfProfile>"
) do (echo %%~a) >> "nvidiaProfileInspector\CoutXProfile.nip"
goto:EOF
)

set Type=%~3
if not defined Type set Type=Dword

for %%a in (
"      <ProfileSetting>"
"        <SettingID>%~1</SettingID>"
"        <SettingValue>%~2</SettingValue>"
"        <ValueType>%Type%</ValueType>"
"      </ProfileSetting>"
) do (echo %%~a) >> "nvidiaProfileInspector\CoutXProfile.nip"
goto:EOF

:DirectXSetting
for /f "tokens=3*" %%a in ('Reg query "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "DirectXUserGlobalSettings" 2^>nul ^| Find "REG_SZ"') do set DirectXSettings=%%a
echo %DirectXSettings% | Find /I "%1" >nul || Reg add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "DirectXUserGlobalSettings" /t REG_SZ /d "%DirectXSettings%%1=%2;" /f >nul && goto:eof
:UpdateDirectXSetting
for /f "tokens=1,* delims=;" %%a in ("%DirectXSettings%") do (
	set DirectXSettings=%%b
	echo %%a | Find /I "%1" >nul && set "UpdatedDirectXSettings=%UpdatedDirectXSettings%%1=%2;"
	echo %%a | Find /I "%1" >nul || set "UpdatedDirectXSettings=%UpdatedDirectXSettings%%%a;"
)
if "%DirectXSettings%" neq "" goto :UpdateDirectXSetting
Reg add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "DirectXUserGlobalSettings" /t REG_SZ /d "%UpdatedDirectXSettings%" /f >nul
set "UpdatedDirectXSettings="
goto:eof
