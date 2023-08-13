@echo off
cd %~dp0

::Enable Delayed Expansion
setlocal EnableDelayedExpansion

::MinSudo
if not exist "MinSudo.exe" exit /b 1

::NVProfileInspector
if not exist "nvidiaProfileInspector\nvidiaProfileInspector.exe" exit /b 3

::Admin
rmdir %SystemDrive%\Windows\system32\adminrightstest >nul 2>&1
mkdir %SystemDrive%\Windows\system32\adminrightstest >nul 2>&1
if "%errorlevel%" neq "0" exit /b 4

::Setup MinSudo
sc query TrustedInstaller 2>nul | find "RUNNING" >nul || (
MinSudo.exe --NoLogo --System Reg add "HKLM\System\CurrentControlSet\Services\TrustedInstaller" /v "Start" /t REG_DWORD /d "3" /f
MinSudo.exe --NoLogo --System sc config "TrustedInstaller" start=demand
MinSudo.exe --NoLogo --System sc start "TrustedInstaller"
)

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

::Quickly kill apps during shutdown
Reg add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "2000" /f >nul
::Quickly end services at shutdown
Reg add "HKLM\System\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "2000" /f >nul
::Kill apps at shutdown
Reg add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f >nul
echo Quick shutdown

::Quickly kill non-respondive apps
Reg add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f >nul
::Quickly show menus
Reg add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "20" /f >nul
echo Speed up windows

::Quick Boot
Reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v "StartupDelayInMSec" /t REG_SZ /d "0" /f >nul
if "%duelboot%" equ "no" (bcdedit /timeout 0) >nul
bcdedit /set bootuxdisabled On >nul
bcdedit /set bootmenupolicy Legacy >nul
bcdedit /set quietboot yes >nul
echo Quick boot

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

::Enable xAPIC
bcdedit /set x2apicpolicy enable >nul
bcdedit /set uselegacyapicmode no >nul
echo Enable xAPIC

::Disable Network Power Savings and Mitigations
powershell -NoProfile -NonInteractive -ExecutionPolicy Unrestricted -Command ^
$ErrorActionPreference = 'SilentlyContinue';^
Disable-NetAdapterPowerManagement -Name "*";^
Get-NetAdapter -IncludeHidden ^| Set-NetIPInterface -WeakHostSend Enabled -WeakHostReceive Enabled;^
Set-NetOffloadGlobalSetting -PacketCoalescingFilter Disabled -Chimney Disabled;^
Set-NetTCPSetting -SettingName "Internet" -MemoryPressureProtection Disabled
echo Disable Network Power Savings And Mitigations

::Set Congestion Provider To BBR2
netsh int tcp set supplemental template=Internet congestionprovider=bbr2 >nul
echo Set Congestion Provider To BBR2

::Disable Nagle's Algorithm
Reg add "HKLM\Software\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f >nul 2>&1  
for /f "tokens=3*" %%i in ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards" /f "ServiceName" /s ^|findstr /i /l "ServiceName"') do (
		Reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
		Reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TcpAckFrequency" /t REG_DWORD /d "1" /f
		Reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TcpDelAckTicks" /t REG_DWORD /d "0" /f
) >nul 2>&1
echo Disable Nagle's Algorithm

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
::Disable JumboPacket
Reg add "%%g" /v "JumboPacket" /t REG_SZ /d "0" /f
::Interrupt Moderation Adaptive (Default)
Reg add "%%g" /v "ITR" /t REG_SZ /d "125" /f
::Receive/Transmit Buffers
Reg add "%%g" /v "ReceiveBuffers" /t REG_SZ /d "266" /f
Reg add "%%g" /v "TransmitBuffers" /t REG_SZ /d "266" /f
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

::Enable Network Task Offloading
Netsh int ip set global taskoffload=enabled >nul 2>&1
Reg add HKLM\SYSTEM\CurrentControlSet\Services\TCPIP\Parameters /v DisableTaskOffload /t REG_DWORD /d 0 /f >nul 2>&1
echo Enable Network Task Offloading

::Disable NetBios
call :ControlSet "Services\NetBT\Parameters\Interfaces" "NetbiosOptions" "2"
rem NetBios is disabled. If it manages to become enabled, protect against NBT-NS poisoning attacks
call :ControlSet "Services\NetBT\Parameters" "NodeType" "2"
echo Disable NetBios

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

::https://docs.microsoft.com/en-us/windows-hardware/drivers/display/gdi-hardware-acceleration
for /f %%a in ('Reg query "HKLM\System\CurrentControlSet\Control\Class" /v "VgaCompatible" /s 2^>nul ^| findstr "HKEY"') do call :ControlSet "%%a" "KMD_EnableGDIAcceleration" "1"
::Enable Hardware Accelerated Scheduling
Reg query "HKLM\System\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchMode" >nul 2>&1 && call :ControlSet "Control\GraphicsDrivers" "HwSchMode" "2"
echo Enable Hardware Accelerated Scheduling

::Enable MSI Mode
for /f %%a in ('wmic path Win32_VideoController get PNPDeviceID ^| find "PCI\VEN_"') do call :ControlSet "Enum\%%a\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" "MSISupported" "1"
echo Enable MSI Mode on GPU
for /f %%a in ('wmic path Win32_USBController get PNPDeviceID ^| find "PCI\VEN_"') do call :ControlSet "Enum\%%a\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" "MSISupported" "1"
echo Enable MSI Mode on USB

rem Turn off Inventory Collector
Reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d "1" /f >nul
rem Turn off Windows Error Reporting
Reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f >nul
rem Disable Application Telemetry
Reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d "0" /f >nul
rem Disable the Customer Experience Improvement program (Below is 0 to disable)
Reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\SQM" /v "DisableCustomerImprovementProgram" /t REG_DWORD /d 0 /f >nul
Reg add "HKLM\Software\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f >nul
Reg add "HKLM\Software\Policies\Microsoft\AppV\CEIP" /v "CEIPEnable" /t REG_DWORD /d "0" /f >nul
Reg add "HKLM\Software\Policies\Microsoft\Messenger\Client" /v "CEIP" /t REG_DWORD /d "2" /f >nul
rem Disable Telemetry (Below is 1 to disable)
Reg add "HKLM\Software\Policies\Microsoft\MSDeploy\3" /v "EnableTelemetry" /t REG_DWORD /d "1" /f >nul
Call :ControlSet "Services\DiagTrack" "Start" "4"
Reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >nul
rem Disable Text/Ink/Handwriting Telemetry
reg add "HKCU\Software\Microsoft\Input\TIPC" /v Enabled /t REG_DWORD /d 0 /f >nul
Reg add "HKLM\Software\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f >nul
Reg add "HKLM\Software\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f >nul
Reg add "HKLM\Software\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d "1" /f >nul
Reg add "HKLM\Software\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d "1" /f >nul
Reg add "HKCU\Software\Microsoft\Personalization\Settings" /v AcceptedPrivacyPolicy /t REG_DWORD /d 0 /f >nul
rem Disable Advertising ID
Reg add "HKLM\Software\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d "1" /f >nul
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f >nul
rem Disable OneDrive Sync
Reg add "HKLM\Software\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d "1" /f >nul
rem Disable Delivery Optimization
Reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings" /v "DownloadMode" /t REG_DWORD /d "0" /f  >nul
echo Disable Telemetry

::Disable Biometrics
Reg add "HKLM\Software\Policies\Microsoft\Biometrics" /v "Enabled" /t REG_DWORD /d "0" /f >nul
echo Disable Biometrics

::Background Apps
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f >nul
Reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsRunInBackground" /t REG_DWORD /d "2" /f >nul
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BackgroundAppGlobalToggle" /t REG_DWORD /d "0" /f >nul
echo Disable Background Apps

::Disable Hibernation
call :ControlSet "Control\Power" "HibernateEnabled" "0"
powercfg /h off >nul
echo Disable Hibernation

::Adjust processor scheduling to allocate processor resources to programs
Reg query "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" 2>nul | find "0x18" >nul && call :ControlSet "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" "Win32PrioritySeparation" "38"
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
sc config NvTelemetyContainer start=disabled >nul
sc stop NvTelemetyContainer >nul
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

::Grab Nvidia Graphics Card Registry Key
for /f %%a in ('Reg query "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /t REG_SZ /s /e /f "NVIDIA" ^| findstr "HKEY"') do (
::Disable HDCP
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
)

::Disable GpuEnergyDrv
call :ControlSet "Services\GpuEnergyDrv" "Start" "4"
echo Disable GpuEnergyDrv

::Disable HPET
bcdedit /set disabledynamictick yes >nul
bcdedit /deletevalue useplatformclock >nul 2>nul
for /f "tokens=2 delims==" %%G in ('wmic OS get buildnumber /value') do for /F "tokens=*" %%x in ("%%G") do (set "VAR=%%~x")
if !VAR! geq 19042 bcdedit /deletevalue useplatformtick >nul 2>nul
if !VAR! lss 19042 bcdedit /set useplatformtick yes >nul
echo Disable HPET

::Restore Power Settings
call :ControlSet "System\Services\NetBT\Parameters" "CsEnabled" "0"
call :ControlSet "System\Services\NetBT\Parameters" "PlatformAoAcOverride" "0"
::Power Plan
powercfg /duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb >nul 2>&1
powercfg /setactive bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb >nul
powercfg /delete eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee >nul 2>&1
powercfg /duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee >nul 2>&1
powercfg /setactive eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee >nul
powercfg /delete bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb >nul
::Throttle States: OFF
powercfg -setacvalueindex scheme_current sub_processor THROTTLING 0 >nul
::Device Idle Policy: Performance
powercfg -setacvalueindex scheme_current sub_none DEVICEIDLE 0 >nul
::Require a password on wakeup: OFF
powercfg -setacvalueindex scheme_current sub_none CONSOLELOCK 0 >nul
::USB 3 Link Power Management: OFF 
powercfg -setacvalueindex scheme_current 2a737441-1930-4402-8d77-b2bebba308a3 d4e98f31-5ffe-4ce1-be31-1b38b384c009 0 >nul
::USB selective suspend setting: OFF
powercfg -setacvalueindex scheme_current 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0 >nul
::Link State Power Management: OFF
powercfg -setacvalueindex scheme_current SUB_PCIEXPRESS ASPM 0 >nul
::AHCI Link Power Management - HIPM/DIPM: OFF
powercfg -setacvalueindex scheme_current SUB_DISK 0b2d69d7-a2a1-449c-9680-f91c70521c60 0 >nul
::NVMe Power State Transition Latency Tolerance
powercfg -setacvalueindex scheme_current SUB_DISK dbc9e238-6de9-49e3-92cd-8c2b4946b472 1 >nul
powercfg -setacvalueindex scheme_current SUB_DISK fc95af4d-40e7-4b6d-835a-56d131dbc80e 1 >nul
::Interrupt Steering
echo %PROCESSOR_IDENTIFIER% | find /I "Intel" >nul && powercfg -setacvalueindex scheme_current SUB_INTSTEER MODE 6 >nul
::TDP Level High
call :ControlSet "Control\Power\PowerSettings\48df9d60-4f68-11dc-8314-0800200c9a66\07029cd8-4664-4698-95d8-43b2e9666596" "ACSettingIndex" "0"
::Enable Hardware P-states
call :ControlSet "Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\4d2b0152-7d5c-498b-88e2-34345392a2c5" "ValueMax" "200000"
powercfg -setacvalueindex scheme_current sub_processor PERFAUTONOMOUS 1 >nul
powercfg -setacvalueindex scheme_current sub_processor PERFAUTONOMOUSWINDOW 20000 >nul
powercfg -setacvalueindex scheme_current sub_processor PERFCHECK 100000 >nul
::Dont restrict core boost
powercfg -setacvalueindex scheme_current sub_processor PERFEPP 0 >nul
::Enable Turbo Boost
powercfg -setacvalueindex scheme_current sub_processor PERFBOOSTMODE 1 >nul
powercfg -setacvalueindex scheme_current sub_processor PERFBOOSTPOL 100 >nul
::Disable Sleep States
powercfg -setacvalueindex scheme_current SUB_SLEEP AWAYMODE 0 >nul
powercfg -setacvalueindex scheme_current SUB_SLEEP ALLOWSTANDBY 0 >nul
powercfg -setacvalueindex scheme_current SUB_SLEEP HYBRIDSLEEP 0 >nul
::Disable Core Parking
echo %PROCESSOR_IDENTIFIER% | find /I "Intel" >nul && (
call :ControlSet "Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" "ValueMax" "100"
powercfg -setacvalueindex scheme_current sub_processor CPMINCORES 100 >nul 2>&1
) || (
powercfg -setacvalueindex scheme_current SUB_INTSTEER UNPARKTIME 0
powercfg -setacvalueindex scheme_current SUB_INTSTEER PERPROCLOAD 10000
)
::Disable Frequency Scaling
powercfg -setacvalueindex scheme_current sub_processor PROCTHROTTLEMIN 100 >nul
::Don't turn off display when plugged in
powercfg /change standby-timeout-ac 0
powercfg /change monitor-timeout-ac 0
powercfg /change hibernate-timeout-ac 0
::Apply Changes
powercfg -setactive scheme_current >nul
powercfg -changename scheme_current "CoutX Ultimate Performance" "For CoutX Optimizer %Version% (discord.gg/CoutX) By UnLovedCookie" >nul
echo CoutX Power Plan

::Optimize Minecraft Settings
PowerShell -nop "[System.Net.ServicePointManager]::SecurityProtocol = 'Tls12';iex(irm https://github.com/couleur-tweak-tips/TweakList/raw/master/Master.ps1); Optimize-OptiFine -Preset Lowest" >nul
echo Optimize Minecraft Settings

::Check GPU
for /f "tokens=2 delims==" %%a in ('wmic path Win32_VideoController get VideoProcessor /value') do (
for %%n in (GeForce NVIDIA RTX GTX) do echo %%a | find "%%n" >nul && set GPU=NVIDIA
)
:::::::::::::::::::::::::::
:::::::::::::::::::::::::::
::::Disable Mitigations::::
:::::::::::::::::::::::::::
:::::::::::::::::::::::::::

Reg query HKCU\Software\CoutX /v DisableMitigations 2>nul | find "0x1" >nul && (
	::222222222222222222222222222222222222222222222222
	::Disable Kernel Mitigations
	for /f "tokens=3 skip=2" %%i in ('Reg query "HKLM\System\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationAuditOptions"') do (
	set "mitigation_mask=%%i"
	for /l %%i in (0,1,9) do set mitigation_mask=!mitigation_mask:%%i=2!
	)
	Reg add "HKLM\System\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationOptions" /t REG_BINARY /d "%mitigation_mask%" /f >nul
	Reg add "HKLM\System\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationAuditOptions" /t REG_BINARY /d "%mitigation_mask%" /f >nul
	::Disable More Kernel Mitigations (Enforced Intel SGX causes boot crashes/loops)
	echo %PROCESSOR_IDENTIFIER% | find /I "Intel" >nul || (
	bcdedit /set isolatedcontext No >nul
	bcdedit /set allowedinmemorysettings 0x0 >nul
	)
	echo Disable Kernel Mitigations
	
	::Disable CSRSS mitigations
	Reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe" /v MitigationAuditOptions /t REG_BINARY /d "%mitigation_mask%" /f >nul
	Reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe" /v MitigationOptions /t REG_BINARY /d "%mitigation_mask%" /f >nul
	echo Disable CSRSS mitigations
	
	::Disable Process Mitigations
	PowerShell -nop "ForEach($v in (Get-Command -Name \"Set-ProcessMitigation\").Parameters[\"Disable\"].Attributes.ValidValues){Set-ProcessMitigation -System -Disable $v.ToString() -ErrorAction SilentlyContinue}" >nul
	echo Disable Process Mitigations
	
	::Disable TsX
	call :ControlSet "Control\Session Manager\kernel" "DisableTsx" "1"
	echo Disable TsX
	
	::Disable CPU Virtualization
	Reg add "HKLM\Software\Policies\Microsoft\Windows\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d "0" /f >nul
	bcdedit /set vsmlaunchtype Off >nul
	bcdedit /set vm No >nul
	echo Disable CPU Virtualization
	
	::Disable Core Isolation
	call :ControlSet "Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" "Enabled" "0"
	bcdedit /set hypervisorlaunchtype off >nul
	echo Disable Core Isolation
	
	::Disable Data Execution Prevention
	echo %PROCESSOR_IDENTIFIER% | find /I "Intel" >nul && (
	bcdedit /set nx AlwaysOff >nul
	Reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Main" /v "DEPOff" /t REG_DWORD /d 1 /f >nul
	Reg add "HKLM\Software\Policies\Microsoft\Windows\Explorer" /v "NoDataExecutionPrevention" /t REG_DWORD /d 1 /f >nul
	Reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "DisableHHDEP" /t REG_DWORD /d 1 /f >nul
	)
	echo Disable Data Execution Prevention
	
	::Enable PAE
	bcdedit /set pae ForceEnable >nul
	echo Enable PAE
	
	::Disable Dma Memory Protection
	Reg add "HKLM\Software\Microsoft\PolicyManager\default\DmaGuard\DeviceEnumerationPolicy" /v "value" /t REG_DWORD /d "2" /f >nul
	Reg add "HKLM\Software\Policies\Microsoft\FVE" /v "DisableExternalDMAUnderLock" /t REG_DWORD /d "0" /f >nul
	Reg add "HKLM\Software\Policies\Microsoft\Windows\DeviceGuard" /v "HVCIMATRequired" /t REG_DWORD /d "0" /f >nul
	echo Disable Dma Remapping / Memory Protection
	
	::Disable SEHOP
	call :ControlSet "Control\Session Manager\kernel" "DisableExceptionChainValidation" "1"
	call :ControlSet "Control\Session Manager\kernel" "KernelSEHOPEnabled" "0"
	echo Disable SEHOP
	
	::Disable Control Flow Guard
	call :ControlSet "Control\Session Manager\Memory Management" "EnableCfg" "0"
	call :ControlSet "Control\Session Manager" "ProtectionMode" "0"
	echo Disable Control Flow Guard
	
	::Disable Spectre And Meltdown
	call :ControlSet "Control\Session Manager\Memory Management" "FeatureSettings" "3"
	call :ControlSet "Control\Session Manager\Memory Management" "FeatureSettingsOverride" "3"
	call :ControlSet "Control\Session Manager\Memory Management" "FeatureSettingsOverrideMask" "3"
	takeown /f "C:\Windows\System32\mcupdate_GenuineIntel.dll" /r /d y >nul 2>&1
	takeown /f "C:\Windows\System32\mcupdate_AuthenticAMD.dll" /r /d y >nul 2>&1
	if exist "%WinDir%\System32\mcupdate_GenuineIntel.dll" MinSudo.exe --TrustedInstaller --Privileged cmd /c "ren %WinDir%\System32\mcupdate_GenuineIntel.dll mcupdate_GenuineIntel.dll.old"
	if exist "%WinDir%\System32\mcupdate_AuthenticAMD.dll" MinSudo.exe --TrustedInstaller --Privileged cmd /c "ren %WinDir%\System32\mcupdate_AuthenticAMD.dll mcupdate_AuthenticAMD.dll.old"
	echo Disable Spectre And Meltdown
	
	::Disable ITLB Multi-hit mitigations
	Reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Virtualization" /v "IfuErrataMitigations" /t REG_DWORD /d "0" /f >nul
	echo Disable ITLB Multi-hit mitigations
	 Reg add HKCU\Software\CoutX /v DisableMitigationsgRan /t REG_DWORD /d 1 /f >nul
) || Reg query HKCU\Software\CoutX /v DisableMitigationsgRan 2>nul | find "0x1" >nul && (
	::Reset Kernel Mitigations
	Reg delete "HKLM\System\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationOptions" /f >nul 2>&1
	Reg delete "HKLM\System\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationAuditOptions" /f >nul 2>&1
	::Reset More Kernel Mitigations
	bcdedit /deletevalue isolatedcontext >nul
	bcdedit /deletevalue allowedinmemorysettings >nul
	
	::Reset CSRSS mitigations
	Reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe" /v MitigationAuditOptions /f >nul 2>&1
	Reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe" /v MitigationOptions /f >nul 2>&1
	
	::Reset System Mitigations
	PowerShell -nop "Set-ProcessMitigation -System -Reset" >nul 2>&1
	
	::Reset TsX
	call :DelControlSet "Control\Session Manager\kernel" "DisableTsx"
	
	::Reset CPU Virtualization
	Reg delete "HKLM\Software\Policies\Microsoft\Windows\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /f >nul 2>&1
	bcdedit /deletevalue vsmlaunchtype >nul
	bcdedit /deletevalue vm >nul
	
	::Reset Core Isolation
	call :DelControlSet "Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" "Enabled"
	bcdedit /deletevalue hypervisorlaunchtype >nul
	
	::Reset Data Execution Prevention
	bcdedit /deletevalue nx >nul
	Reg delete "HKLM\Software\Policies\Microsoft\Internet Explorer\Main" /v "DEPOff" /f >nul 2>&1
	Reg delete "HKLM\Software\Policies\Microsoft\Windows\Explorer" /v "NoDataExecutionPrevention" /f >nul 2>&1
	Reg delete "HKLM\Software\Policies\Microsoft\Windows\System" /v "DisableHHDEP" /f >nul 2>&1
	
	::Reset PAE
	bcdedit /deletevalue pae >nul
	
	::Reset Dma Memory Protection
	Reg delete "HKLM\Software\Microsoft\PolicyManager\default\DmaGuard\DeviceEnumerationPolicy" /v "value" /f >nul 2>&1
	Reg delete "HKLM\Software\Policies\Microsoft\FVE" /v "DisableExternalDMAUnderLock" /f >nul 2>&1
	Reg delete "HKLM\Software\Policies\Microsoft\Windows\DeviceGuard" /v "HVCIMATRequired" /f >nul 2>&1
	
	::Reset SEHOP
	call :DelControlSet "Control\Session Manager\kernel" "DisableExceptionChainValidation" "1"
	call :DelControlSet "Control\Session Manager\kernel" "KernelSEHOPEnabled" "0"
	
	::Reset Control Flow Guard
	call :DelControlSet "Control\Session Manager\Memory Management" "EnableCfg"
	call :DelControlSet "Control\Session Manager" "ProtectionMode"
	
	::Reset Spectre And Meltdown
	call :DelControlSet "Control\Session Manager\Memory Management" "FeatureSettings"
	call :DelControlSet "Control\Session Manager\Memory Management" "FeatureSettingsOverride"
	call :DelControlSet "Control\Session Manager\Memory Management" "FeatureSettingsOverrideMask"
	takeown /f "C:\Windows\System32\mcupdate_GenuineIntel.dll.old" /r /d y >nul 2>&1
	takeown /f "C:\Windows\System32\mcupdate_AuthenticAMD.dll.old" /r /d y >nul 2>&1
	if exist "%WinDir%\System32\mcupdate_GenuineIntel.dll" MinSudo.exe --TrustedInstaller --Privileged cmd /c "ren %WinDir%\System32\mcupdate_GenuineIntel.dll.old mcupdate_GenuineIntel.dll" >nul 2>&1
	if exist "%WinDir%\System32\mcupdate_AuthenticAMD.dll" MinSudo.exe --TrustedInstaller --Privileged cmd /c "ren %WinDir%\System32\mcupdate_AuthenticAMD.dll.old mcupdate_AuthenticAMD.dll" >nul 2>&1
	echo Reset Mitigations
	
	::Reset ITLB Multi-hit mitigations
	Reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Virtualization" /v "IfuErrataMitigations" /t REG_DWORD /d "0" /f >nul
	echo Reset ITLB Multi-hit mitigations
	Reg delete HKCU\Software\CoutX /v DisableMitigationsgRan /f >nul
)

::::::::::::::::::::::::::::::::::::
::::::::::::::::::::::::::::::::::::
::::Disable GPU Power Throttling::::
::::::::::::::::::::::::::::::::::::
::::::::::::::::::::::::::::::::::::

Reg query HKCU\Software\CoutX /v DisableGPUThrottling 2>nul | find "0x1" >nul && (
	::NVCP
	del /F /Q "nvidiaProfileInspector\EchoProfile.nip"
	::Enable Ultra Low Latency
	call :NVCP "390467" "2"
	call :NVCP "277041152" "1"
	::Prefer Maximum Performance
	call :NVCP "274197361" "1"
	::Enable Anisotropic Optimizations
	call :NVCP "8703344" "1"
	call :NVCP "15151633" "1"
	::Set Texture Filtering to High Performance
	call :NVCP "13510289" "20"
	call :NVCP "13510290" "1"
	::Disable Cuda P2 State
	call :NVCP "1343646814" "0"
	::Enable All Thread Optimizations
	call :NVCP "539870258" "31"
	call :NVCP "544902290" "31"
	call :NVCP "544902290" "31"
	::Enable rBAR
	call :NVCP "983226" "1"
	call :NVCP "983227" "1"
	call :NVCP "983295" "AAAAQAAAAAA=" "Binary"
	call :NVCP "End"
	if "%GPU%" equ "NVIDIA" start "" /D "nvidiaProfileInspector" nvidiaProfileInspector.exe EchoProfile.nip
	echo NVCP Settings

	::Grab Nvidia Graphics Card Registry Key
	for /f %%a in ('Reg query "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /t REG_SZ /s /e /f "NVIDIA" ^| findstr "HKEY"') do (
	::Nvidia PState 0
	Reg query "%%a" /v "DisableDynamicPState" >nul 2>&1 && Call :ControlSet "%%a" "DisableDynamicPState" "1"
	echo Disable Nvidia PStates
	::Enable KBoost
	Call :ControlSet "%%a" "PowerMizerEnable" "1"
	Call :ControlSet "%%a" "PowerMizerLevel" "1"
	Call :ControlSet "%%a" "PowerMizerLevelAC" "1"
	Call :ControlSet "%%a" "PerfLevelSrc" "8738"
	echo Enable KBoost
	::Disable Core Downclock
	Call :ControlSet "%%a" "EnableCoreSlowdown" "0"
	Call :ControlSet "%%a" "EnableMClkSlowdown" "0"
	Call :ControlSet "%%a" "EnableNVClkSlowdown" "0"
	echo Disable Core Downclock
	)
	
	::Grab iGPU Registry Key
	for /f %%i in ('Reg query "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /t REG_SZ /s /e /f "Intel" ^| findstr "HKEY"') do (
	::Disable iGPU CStates
	Call :ControlSet "%%i" "AllowDeepCStates" "0"
	echo Disable iGPU CStates
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
	::NVCP
	del /F /Q "nvidiaProfileInspector\EchoProfile.nip"
	::Prefer Optimal Performance
	call :NVCP "274197361" "5"
	call :NVCP "End"
	if "%GPU%" equ "NVIDIA" start "" /D "nvidiaProfileInspector" nvidiaProfileInspector.exe EchoProfile.nip
	echo Reset NVCP Settings

	for /f %%a in ('Reg query "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /t REG_SZ /s /e /f "NVIDIA" ^| findstr "HKEY"') do (
	Reg query "%%a" /v "DisableDynamicPState" >nul 2>&1 && Call :ControlSet "%%a" "DisableDynamicPState" "0"
	echo Reset Nvidia PStates
	Call :DelControlSet "%%a" "PowerMizerEnable"
	Call :DelControlSet "%%a" "PowerMizerLevel"
	Call :DelControlSet "%%a" "PowerMizerLevelAC"
	Call :DelControlSet "%%a" "PerfLevelSrc"
	echo Reset KBoost
	Call :DelControlSet "%%a" "EnableCoreSlowdown"
	Call :DelControlSet "%%a" "EnableMClkSlowdown"
	Call :DelControlSet "%%a" "EnableNVClkSlowdown"
	echo Reset Core Downclock
	)
	
	::Grab iGPU Registry Key
	for /f %%i in ('Reg query "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /t REG_SZ /s /e /f "Intel" ^| findstr "HKEY"') do (
	::Reset iGPU CStates
	Call :DelControlSet "%%i" "AllowDeepCStates" "0"
	echo Reset iGPU CStates
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
	echo Disable Idle

	::Disable System Clock
	bcdedit /set disabledynamictick yes >nul 2>&1
	bcdedit /deletevalue useplatformclock >nul 2>&1
	for /F "tokens=2 delims==" %%G in ('wmic OS get buildnumber /value') do @for /F "tokens=*" %%x in ("%%G") do (set "VAR=%%~x")
	if !VAR! geq 19042 (bcdedit /deletevalue useplatformtick >nul 2>&1
	) else (bcdedit /set useplatformtick yes >nul 2>&1
	)
	echo Disable System Clock
	
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
	
	::Disable the Processor Power Management Driver
	call :ControlSet "Services\IntelPPM" "Start" "4"
	call :ControlSet "Services\AmdPPM" "Start" "4"
	echo Disable the Processor Power Management Driver
	
	 Reg add HKCU\Software\CoutX /v DisableCPUThrottlingRan /t REG_DWORD /d 1 /f >nul
) || Reg query HKCU\Software\CoutX /v DisableCPUThrottlingRan 2>nul | find "0x1" >nul && (
	::System Clock
	bcdedit /deletevalue useplatformclock >nul 2>&1
	bcdedit /deletevalue useplatformtick >nul 2>&1
	bcdedit /deletevalue disabledynamictick >nul 2>&1
	echo Reset System Clock
	
	::Timer Resolution
	net stop STR >nul 2>&1
	%systemdrive%\SetTimerResolution.exe -Uninstall >nul 2>&1
	del /f "%systemdrive%\SetTimerResolution.exe" 2>nul
	::QoS Timer Resolution
	Reg delete "HKLM\Software\Policies\Microsoft\Windows\Psched" /v "TimerResolution" /f >nul 2>&1
	echo Reset Timer Resolution
	
	::Reset QoS Timer Resolution
	Reg delete "HKLM\Software\Policies\Microsoft\Windows\Psched" /v "TimerResolution" /f >nul 2>&1
	echo Reset QoS TimerResolution

	::Enable the Processor Power Management Driver
	call :ControlSet "Services\IntelPPM" "Start" "2"
	call :ControlSet "Services\AmdPPM" "Start" "2"
	echo Enable the Processor Power Management Driver

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
	
	::Set SvcSplitThreshold
	for /f "tokens=2 delims==" %%n in ('wmic os get TotalVisibleMemorySize /format:value') do set mem=%%n
	set /a ram=!mem! + 1024000
	call :ControlSet "Control" "SvcHostSplitThresholdInKB" "!ram!"
	echo SvcSplitThreshold

	::Disable Large System Cache
	call :ControlSet "Control\Session Manager\Memory Management" "LargeSystemCache" "1"
	echo Disable Large System Cache

	::Disable Prefetch
	sc config "SysMain" start=disabled >nul
	sc stop "SysMain" >nul
	call :ControlSet "Control\Session Manager\Memory Management\PrefetchParameters" "EnablePrefetcher" "0"
	call :ControlSet "Control\Session Manager\Memory Management\PrefetchParameters" "EnableSuperfetch" "0"
	call :ControlSet "Control\Session Manager\Memory Management\PrefetchParameters" "EnableBoottrace" "0"
	echo Disable Prefetch

	::Disable Preemption
	call :ControlSet "Control\GraphicsDrivers\Scheduler" "EnablePreemption" "0"
	echo Disable Preemption

	::Disable Write Combining
	call :ControlSet "Services\nvlddmkm" "DisableWriteCombining" "1"
	echo Disable Write Combining
	
	::Force Contigous Memory Allocation
	for /f %%a in ('Reg query "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /t REG_SZ /s /e /f "NVIDIA" ^| findstr "HKEY"') do (
	call :ControlSet "%%a" "PreferSystemMemoryContiguous" "1"
	)
	
	 Reg add HKCU\Software\CoutX /v ExTweaksRan /t REG_DWORD /d 1 /f >nul
) || Reg query HKCU\Software\CoutX /v ExTweaksRan 2>nul | find "0x1" >nul && (
	sc config "SysMain" start=auto >nul
	sc start "SysMain" >nul
	call :DelControlSet "Control\Session Manager\Memory Management" "DisablePagingExecutive"
	call :DelControlSet "Control\Session Manager\Memory Management" "DisablePageCombining"
	call :DelControlSet "Control\Session Manager\Memory Management" "LargeSystemCache"
	call :DelControlSet "Control\Session Manager\Memory Management\PrefetchParameters" "EnablePrefetcher"
	call :DelControlSet "Control\Session Manager\Memory Management\PrefetchParameters" "EnableSuperfetch"
	call :DelControlSet "Control\Session Manager\Memory Management\PrefetchParameters" "EnableBoottrace"
	call :DelControlSet "Control\GraphicsDrivers\Scheduler" "EnablePreemption"
	call :DelControlSet "Services\nvlddmkm" "DisableWriteCombining"
	call :DelControlSet "Control" "SvcHostSplitThresholdInKB"
	for /f %%a in ('Reg query "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /t REG_SZ /s /e /f "NVIDIA" ^| findstr "HKEY"') do (
	call :DelControlSet "%%a" "PreferSystemMemoryContiguous"
	)
	Reg delete HKCU\Software\CoutX /v ExTweaksRan /f >nul
)

::Flush DNS
ipconfig /flushdns >nul
::Update Group Policy 
gpupdate /force >nul
::Restart Explorer
(taskkill /f /im explorer.exe && start explorer.exe) >nul
::End
taskkill /f /im regedit.exe >nul 2>&1
taskkill /f /im MinSudo.exe >nul 2>&1
taskkill /f /im fsutil.exe >nul 2>&1
exit 0

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

if not exist "nvidiaProfileInspector\EchoProfile.nip" (
echo ^<?xml version="1.0" encoding="utf-16"?^> > "nvidiaProfileInspector\EchoProfile.nip"
for %%a in (
"<ArrayOfProfile>"
"  <Profile>"
"    <ProfileName>Base Profile</ProfileName>"
"    <Executeables />"
"    <Settings>"
) do (echo %%~a) >> "nvidiaProfileInspector\EchoProfile.nip"
)

if "%~1" equ "End" (
for %%a in (
"    </Settings>"
"  </Profile>"
"</ArrayOfProfile>"
) do (echo %%~a) >> "nvidiaProfileInspector\EchoProfile.nip"
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
) do (echo %%~a) >> "nvidiaProfileInspector\EchoProfile.nip"
goto:EOF
