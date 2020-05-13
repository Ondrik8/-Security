## CyberSEC & anti-SPY



```bash
'╔═╗┌─┐┌─┐┬ ┬┬─┐┬┌┬┐┬ ┬
'╚═╗├┤ │ │ │├┬┘│ │ └┬┘
'╚═╝└─┘└─┘└─┘┴└─┴ ┴ ┴ 
Все о вопросах безопасности.
```

````
:: Windows 10 Hardening Script
:: This is based mostly on my own personal research and testing. My objective is to secure/harden Windows 10 as much as possible while not impacting usability at all. (Think being able to run on this computer's of family members so secure them but not increase the chances of them having to call you to troubleshoot something related to it later on). References for virtually all settings can be found at the bottom. Just before the references section, you will always find several security settings commented out as they could lead to compatibility issues in common consumer setups but they're worth considering. 
:: Obligatory 'views are my own'. :) 
:: Thank you @jaredhaight for the Win Firewall config recommendations!
:: Thank you @ricardojba for the DLL Safe Order Search reg key! 
:: Thank you @jessicaknotts for the help on testing Exploit Guard configs and checking privacy settings!
:: Best script I've found for Debloating Windows 10: https://github.com/Sycnex/Windows10Debloater
::
::#######################################################################
::
:: Change file associations to protect against common ransomware attacks
:: Note that if you legitimately use these extensions, like .bat, you will now need to execute them manually from cmd or powershel
:: Alternatively, you can right-click on them and hit 'Run as Administrator' but ensure it's a script you want to run :) 
:: https://support.microsoft.com/en-us/help/883260/information-about-the-attachment-manager-in-microsoft-windows
:: ---------------------
ftype htafile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
ftype wshfile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
ftype wsffile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
ftype batfile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
ftype jsfile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
ftype jsefile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
ftype vbefile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
ftype vbsfile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
::
::#######################################################################
:: Enable and configure Windows Defender and advanced settings
::#######################################################################
::
:: Reset Defender to defaults. Commented out but available for reference
::"%programfiles%"\"Windows Defender"\MpCmdRun.exe -RestoreDefaults
:: https://docs.microsoft.com/en-us/windows/client-management/mdm/policy-csp-defender#defender-submitsamplesconsent
:: https://docs.microsoft.com/en-us/powershell/module/defender/set-mppreference?view=win10-ps
::
:: Start Defender Service
sc start WinDefend
::Enable Windows Defender sandboxing
setx /M MP_FORCE_USE_SANDBOX 1
:: Update signatures
"%ProgramFiles%"\"Windows Defender"\MpCmdRun.exe -SignatureUpdate
:: Enable Defender signatures for Potentially Unwanted Applications (PUA)
powershell.exe Set-MpPreference -PUAProtection enable
:: Enable Defender periodic scanning
reg add "HKCU\SOFTWARE\Microsoft\Windows Defender" /v PassiveMode /t REG_DWORD /d 2 /f
:: Enable Cloud functionality of Windows Defender
powershell.exe Set-MpPreference -MAPSReporting Advanced
powershell.exe Set-MpPreference -SubmitSamplesConsent 0
::
:: Enable early launch antimalware driver for scan of boot-start drivers
:: 3 is the default which allows good, unknown and 'bad but critical'. Recommend trying 1 for 'good and unknown' or 8 which is 'good only'
reg add "HKCU\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" /v DriverLoadPolicy /t REG_DWORD /d 3 /f
::
:: Enable ASR rules in Win10 1903 ExploitGuard to mitigate Office malspam
:: Blocks Office childprocs, Office proc injection, Office win32 api calls & executable content creation
:: Note these only work when Defender is your primary AV
::
:: Block Office Child Process Creation 
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled
:: Block Process Injection
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions Enabled
:: Block Win32 API calls in macros
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B -AttackSurfaceReductionRules_Actions Enabled
:: Block Office from creating executables
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 -AttackSurfaceReductionRules_Actions Enabled
:: Block execution of potentially obfuscated scripts
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC -AttackSurfaceReductionRules_Actions Enabled
:: Block executable content from email client and webmail
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions Enabled
:: Block JavaScript or VBScript from launching downloaded executable content
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions Enabled
:: Block lsass cred theft
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions Enabled
:: Block untrusted and unsigned processes that run from USB
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 -AttackSurfaceReductionRules_Actions Enabled
:: Block Adobe Reader from creating child processes
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c -AttackSurfaceReductionRules_Actions Enabled
:: Block persistence through WMI event subscription
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids e6db77e5-3df2-4cf1-b95a-636979351e5b -AttackSurfaceReductionRules_Actions Enabled
:: Block process creations originating from PSExec and WMI commands
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids d1e49aac-8f56-4280-b9ba-993a6d77406c -AttackSurfaceReductionRules_Actions Enabled
::
:: Enable Defender exploit system-wide protection
:: The commented line includes CFG which can cause issues with apps like Discord & Mouse Without Borders
:: powershell.exe Set-Processmitigation -System -Enable DEP,EmulateAtlThunks,BottomUp,HighEntropy,SEHOP,SEHOPTelemetry,TerminateOnError,CFG
powershell.exe Set-Processmitigation -System -Enable DEP,EmulateAtlThunks,BottomUp,HighEntropy,SEHOP,SEHOPTelemetry,TerminateOnError
::
::#######################################################################
:: Enable and Configure Internet Browser Settings
::#######################################################################
::
:: Enable SmartScreen for Edge
reg add "HKCU\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 1 /f
:: Enable Notifications in IE when a site attempts to install software
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer" /v SafeForScripting /t REG_DWORD /d 0 /f
:: Disable Edge password manager to encourage use of proper password manager
reg add "HKCU\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" /v "FormSuggest Passwords" /t REG_SZ /d no /f
::
::#######################################################################
:: Enable and Configure Google Chrome Internet Browser Settings
::#######################################################################
::
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AdvancedProtectionAllowed" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AllowCrossOriginAuthPrompt" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AlwaysOpenPdfExternally" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AmbientAuthenticationInPrivateModesEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AudioCaptureAllowed" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AudioSandboxEnabled" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "BlockExternalExtensions" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DnsOverHttpsMode" /t REG_SZ /d on /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "SSLVersionMin" /t REG_SZ /d tls1 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "ScreenCaptureAllowed" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "SitePerProcess" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "TLS13HardeningForLocalAnchorsEnabled" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "VideoCaptureAllowed" /t REG_DWORD /d 0 /f
::
::#######################################################################
:: Enable and Configure Microsoft Office Security Settings
::#######################################################################
::
:: Harden all version of MS Office itself against common malspam attacks
:: Disables Macros, enables ProtectedView
:: ---------------------
reg add "HKCU\Software\Policies\Microsoft\Office\12.0\Publisher\Security" /v vbawarnings /t REG_DWORD /d 4 /f
reg add "HKCU\Software\Policies\Microsoft\Office\12.0\Word\Security" /v vbawarnings /t REG_DWORD /d 4 /f
reg add "HKCU\Software\Policies\Microsoft\Office\14.0\Publisher\Security" /v vbawarnings /t REG_DWORD /d 4 /f
reg add "HKCU\Software\Policies\Microsoft\Office\14.0\Word\Security" /v vbawarnings /t REG_DWORD /d 4 /f
reg add "HKCU\Software\Policies\Microsoft\Office\15.0\Outlook\Security" /v markinternalasunsafe /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Policies\Microsoft\Office\15.0\Word\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Office\15.0\Excel\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Office\15.0\PowerPoint\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Office\15.0\Word\Security" /v vbawarnings /t REG_DWORD /d 4 /f
reg add "HKCU\Software\Policies\Microsoft\Office\15.0\Publisher\Security" /v vbawarnings /t REG_DWORD /d 4 /f
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Outlook\Security" /v markinternalasunsafe /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Word\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Excel\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\PowerPoint\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Word\Security" /v vbawarnings /t REG_DWORD /d 4 /f
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Publisher\Security" /v vbawarnings /t REG_DWORD /d 4 /f
::
:: Harden all version of MS Office itself against DDE malspam attacks
:: Disables Macros, enables ProtectedView
:: ---------------------
::
reg add "HKCU\Software\Microsoft\Office\14.0\Word\Options" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f
reg add "HKCU\Software\Microsoft\Office\14.0\Word\Options\WordMail" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f
reg add "HKCU\Software\Microsoft\Office\15.0\Word\Options" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f
reg add "HKCU\Software\Microsoft\Office\15.0\Word\Options\WordMail" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f
reg add "HKCU\Software\Microsoft\Office\16.0\Word\Options" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f
reg add "HKCU\Software\Microsoft\Office\16.0\Word\Options\WordMail" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f
::
::#######################################################################
:: Enable and Configure General Windows Security Settings
::#######################################################################
:: Disables DNS multicast, smart mutli-homed resolution, netbios, powershellv2, printer driver download and printing over http, icmp redirect
:: Enables UAC and sets to always notify, Safe DLL loading (DLL Hijacking prevention), saving zone information, explorer DEP, explorer shell protocol protected mode
:: ---------------------
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v DisableSmartNameResolution /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v DisableParallelAandAAAA /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB1 /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v IGMPLevel /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v DisableIPSourceRouting /t REG_DWORD /d 2 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v EnableICMPRedirect /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v DisableIPSourceRouting /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableVirtualization /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v SafeDLLSearchMode /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v ProtectionMode /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v SaveZoneInformation /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v NoDataExecutionPrevention /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v NoHeapTerminationOnCorruption /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v PreXPSP2ShellProtocolBehavior /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers" /v DisableWebPnPDownload /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers" /v DisableHTTPPrinting /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" /v AutoConnectAllowedOEM /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" /v fMinimizeConnections /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netbt\Parameters" /v NoNameReleaseOnDemand /t REG_DWORD /d 1 /f
wmic /interactive:off nicconfig where (TcpipNetbiosOptions=0 OR TcpipNetbiosOptions=1) call SetTcpipNetbios 2
powershell.exe Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -norestart
powershell.exe Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -norestart
::
:: Prioritize ECC Curves with longer keys
reg add "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" /v EccCurves /t REG_MULTI_SZ /d NistP384,NistP256 /f
:: Prevent Kerberos from using DES or RC4
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" /v SupportedEncryptionTypes /t REG_DWORD /d 2147483640 /f
:: Encrypt and sign outgoing secure channel traffic when possible
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v SealSecureChannel /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v SignSecureChannel /t REG_DWORD /d 1 /f
::
:: Enable SmartScreen
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableSmartScreen /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v ShellSmartScreenLevel /t REG_SZ /d Block /f
::
:: Enforce device driver signing
BCDEDIT /set nointegritychecks OFF
::
:: Windows Update Settings
:: Prevent Delivery Optimization from downloading Updates from other computers across the internet
:: 1 will restrict to LAN only. 0 will disable the feature entirely
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v DODownloadMode /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config\" /v DODownloadMode /t REG_DWORD /d 1 /f
::
:: Set screen saver inactivity timeout to 15 minutes
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v InactivityTimeoutSecs /t REG_DWORD /d 900 /f
:: Enable password prompt on sleep resume while plugged in and on battery
reg add "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" /v ACSettingIndex /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" /v DCSettingIndex /t REG_DWORD /d 1 /f
::
:: Windows Remote Access Settings
:: Disable solicited remote assistance
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fAllowToGetHelp /t REG_DWORD /d 0 /f
:: Require encrypted RPC connections to Remote Desktop
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fEncryptRPCTraffic /t REG_DWORD /d 1 /f
:: Prevent sharing of local drives via Remote Desktop Session Hosts
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fDisableCdm /t REG_DWORD /d 1 /f
:: 
:: Removal Media Settings
:: Disable autorun/autoplay on all drives
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v NoAutoplayfornonVolume /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoAutorun /t REG_DWORD /d 1 /f
::
:: Windows Sharing/SMB Settings
:: Disable smb1, anonymous access to named pipes/shared, anonymous enumeration of SAM accounts, non-admin remote access to SAM
:: Enable optional SMB client signing
powershell.exe Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol -norestart
reg add "HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB1 /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" /v RestrictNullSessAccess /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymousSAM /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymous /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v EveryoneIncludesAnonymous /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictRemoteSAM /t REG_SZ /d "O:BAG:BAD:(A;;RC;;;BA)" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v UseMachineId /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0" /v allownullsessionfallback /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 1 /f
:: Force SMB server signing
:: This could cause impact if the Windows computer this is run on is hosting a file share and the other computers connecting to it do not have SMB client signing enabled.
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f
::
:: Harden lsass to help protect against credential dumping (mimikatz) and audit lsass access requests
:: Configures lsass.exe as a protected process and disables wdigest
:: Enables delegation of non-exported credentials which enables support for Restricted Admin Mode or Remote Credential Guard
:: ---------------------
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v AuditLevel /t REG_DWORD /d 00000008 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 00000001 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" /v AllowProtectedCreds /t REG_DWORD /d 1 /f
::
:: Windows RPC and WinRM settings
:: Stop WinRM
net stop WinRM
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" /v AllowUnencryptedTraffic /t REG_DWORD /d 0 /f
:: Prevent unauthenticated RPC connections
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" /v RestrictRemoteClients /t REG_DWORD /d 1 /f
:: Disable WinRM Client Digiest authentication
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" /v AllowDigest /t REG_DWORD /d 0 /f
:: Disabling RPC usage from a remote asset interacting with scheduled tasks
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule" /v DisableRpcOverTcp /t REG_DWORD /d 1 /f
:: Disabling RPC usage from a remote asset interacting with services
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control" /v DisableRemoteScmEndpoints /t REG_DWORD /d 1 /f
::
:: Biometrics
:: Enable anti-spoofing for facial recognition
reg add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" /v EnhancedAntiSpoofing /t REG_DWORD /d 1 /f
:: Disable other camera use while screen is locked
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v NoLockScreenCamera /t REG_DWORD /d 1 /f
:: Prevent Windows app voice activation while locked
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsActivateWithVoiceAboveLock /t REG_DWORD /d 2 /f
:: Prevent Windows app voice activation entirely (be mindful of those with accesibility needs)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsActivateWithVoice /t REG_DWORD /d 2 /f
::
::#######################################################################
:: Enable and configure Windows Firewall
::#######################################################################
::
NetSh Advfirewall set allprofiles state on
::
:: Enable Firewall Logging
netsh advfirewall set currentprofile logging filename %systemroot%\system32\LogFiles\Firewall\pfirewall.log
netsh advfirewall set currentprofile logging maxfilesize 4096
netsh advfirewall set currentprofile logging droppedconnections enable
::
:: Block all inbound connections on Public profile
netsh advfirewall set publicprofile firewallpolicy blockinboundalways,allowoutbound
:: Enable Windows Defender Network Protection
powershell.exe Set-MpPreference -EnableNetworkProtection Enabled
::
:: Block Win32 binaries from making netconns when they shouldn't - specifically targeting native processes known to be abused by bad actors
:: ---------------------
Netsh.exe advfirewall firewall add rule name="Block Notepad.exe netconns" program="%systemroot%\system32\notepad.exe" protocol=tcp dir=out enable=yes action=block profile=any
Netsh.exe advfirewall firewall add rule name="Block regsvr32.exe netconns" program="%systemroot%\system32\regsvr32.exe" protocol=tcp dir=out enable=yes action=block profile=any
Netsh.exe advfirewall firewall add rule name="Block calc.exe netconns" program="%systemroot%\system32\calc.exe" protocol=tcp dir=out enable=yes action=block profile=any
Netsh.exe advfirewall firewall add rule name="Block mshta.exe netconns" program="%systemroot%\system32\mshta.exe" protocol=tcp dir=out enable=yes action=block profile=any
Netsh.exe advfirewall firewall add rule name="Block wscript.exe netconns" program="%systemroot%\system32\wscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
Netsh.exe advfirewall firewall add rule name="Block cscript.exe netconns" program="%systemroot%\system32\cscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
Netsh.exe advfirewall firewall add rule name="Block runscripthelper.exe netconns" program="%systemroot%\system32\runscripthelper.exe" protocol=tcp dir=out enable=yes action=block profile=any
Netsh.exe advfirewall firewall add rule name="Block hh.exe netconns" program="%systemroot%\system32\hh.exe" protocol=tcp dir=out enable=yes action=block profile=any
::
::#######################################################################
:: Windows 10 Privacy Settings
::#######################################################################
::
:: Set Windows Analytics to limited enhanced if enhanced is enabled
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v LimitEnhancedDiagnosticDataWindowsAnalytics /t REG_DWORD /d 1 /f
:: Set Windows Telemetry to security only
:: If you intend to use Enhanced for Windows Analytics then set this to "2" instead
:: Note my understanding is W10 Home edition will do a minimum of "Basic"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v MaxTelemetryAllowed /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v ShowedToastAtLevel /t REG_DWORD /d 1 /f
:: Disable location data
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore" /v Location /t REG_SZ /d Deny /f
:: Prevent the Start Menu Search from providing internet results and using your location
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v BingSearchEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v AllowSearchToUseLocation /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v CortanaConsent /t REG_DWORD /d 0 /f
:: Disable publishing of Win10 user activity 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v PublishUserActivities /t REG_DWORD /d 1 /f
:: Disable Win10 settings sync to cloud
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v DisableSettingSync /t REG_DWORD /d 2 /f
:: Disable the advertising ID
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v DisabledByGroupPolicy /t REG_DWORD /d 1 /f
::
:: Disable Windows GameDVR (Broadcasting and Recording)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v AllowGameDVR /t REG_DWORD /d 0 /f
:: Disable Microsoft consumer experience which prevent notifications of suggested applications to install
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SystemPaneSuggestionsEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SilentInstalledAppsEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v PreInstalledAppsEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v OemPreInstalledAppsEnabled /t REG_DWORD /d 0 /f
:: Disable websites accessing local language list
reg add "HKCU\Control Panel\International\User Profile" /v HttpAcceptLanguageOptOut /t REG_DWORD /d 1 /f
:: Prevent toast notifications from appearing on lock screen
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v NoToastApplicationNotificationOnLockScreen /t REG_DWORD /d 1 /f
::
::#######################################################################
:: Enable Advanced Windows Logging
::#######################################################################
::
:: Enlarge Windows Event Security Log Size
wevtutil sl Security /ms:1024000 /f
wevtutil sl Application /ms:1024000 /f
wevtutil sl System /ms:1024000 /f
wevtutil sl "Windows Powershell" /ms:1024000 /f
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:1024000 /f
:: Record command line data in process creation events eventid 4688
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
::
:: Enabled Advanced Settings
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1 /f
:: Enable PowerShell Logging
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
::
:: Enable Windows Event Detailed Logging
:: This is intentionally meant to be a subset of expected enterprise logging as this script may be used on consumer devices.
:: For more extensive Windows logging, I recommend https://www.malwarearchaeology.com/cheat-sheets
Auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
Auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
Auditpol /set /subcategory:"Logoff" /success:enable /failure:disable
Auditpol /set /subcategory:"Logon" /success:enable /failure:enable 
Auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:disable
Auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable
Auditpol /set /subcategory:"SAM" /success:disable /failure:disable
Auditpol /set /subcategory:"Filtering Platform Policy Change" /success:disable /failure:disable
Auditpol /set /subcategory:"IPsec Driver" /success:enable /failure:enable
Auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
Auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable
Auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable
::
::#######################################################################
:: Extra settings commented out but worth considering
::#######################################################################
::
:: Uninstall common extra apps found on a lot of Win10 installs
:: Obviously do a quick review to ensure it isn't removing any apps you or your user need to use.
:: https://docs.microsoft.com/en-us/windows/application-management/apps-in-windows-10
:: PowerShell command to reinstall all pre-installed apps below
:: Get-AppxPackage -AllUsers| Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
powershell.exe -command "Get-AppxPackage *Microsoft.BingWeather* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.DesktopAppInstaller* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.GetHelp* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Getstarted* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Messaging* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Microsoft3DViewer* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.MicrosoftOfficeHub* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.MicrosoftSolitaireCollection* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.MicrosoftStickyNotes* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.MixedReality.Portal* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Office.OneNote* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.OneConnect* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Print3D* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.SkypeApp* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Wallet* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.WebMediaExtensions* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.WebpImageExtension* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.WindowsAlarms* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.WindowsCamera* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *microsoft.windowscommunicationsapps* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.WindowsFeedbackHub* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.WindowsMaps* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.WindowsSoundRecorder* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Xbox.TCUI* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.XboxApp* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.XboxGameOverlay* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.XboxGamingOverlay* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.XboxIdentityProvider* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.XboxSpeechToTextOverlay* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.YourPhone* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.ZuneMusic* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.ZuneVideo* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.WindowsFeedback* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Windows.ContactSupport* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *PandoraMedia* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *AdobeSystemIncorporated. AdobePhotoshop* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Duolingo* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.BingNews* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Office.Sway* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Advertising.Xaml* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Services.Store.Engagement* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *ActiproSoftware* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *EclipseManager* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *SpotifyAB.SpotifyMusic* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *king.com.* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.NET.Native.Framework.1.* -AllUsers | Remove-AppxPackage"
::
::#######################################################################
:: Extra settings commented out but worth considering
::#######################################################################
::
:: Enforce NTLMv2 and LM authentication
:: This is commented out by default as it could impact access to consumer-grade file shares but it's a recommended setting
:: reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel /t REG_DWORD /d 5 /f
::
:: Prevent unencrypted passwords being sent to third-party SMB servers
:: This is commented out by default as it could impact access to consumer-grade file shares but it's a recommended setting
:: reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v EnablePlainTextPassword /t REG_DWORD /d 0 /f
::
:: Prevent guest logons to SMB servers
:: This is commented out by default as it could impact access to consumer-grade file shares but it's a recommended setting
:: reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" /v AllowInsecureGuestAuth /t REG_DWORD /d 0 /f
::
:: Force SMB server signing
:: This is commented out by default as it could impact access to consumer-grade file shares but it's a recommended setting
:: reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f
::
:: Enable Windows Defender Application Guard
:: This setting is commented out as it enables subset of DC/CG which renders other virtualization products unsuable. Can be enabled if you don't use those
:: powershell.exe Enable-WindowsOptionalFeature -online -FeatureName Windows-Defender-ApplicationGuard -norestart
::
:: Enable Windows Defender Credential Guard
:: This setting is commented out as it enables subset of DC/CG which renders other virtualization products unsuable. Can be enabled if you don't use those
:: reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 1 /f
:: reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v RequirePlatformSecurityFeatures /t REG_DWORD /d 3 /f
:: reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v LsaCfgFlags /t REG_DWORD /d 1 /f
::
:: The following variant also enables forced ASLR and CFG but causes issues with several third party apps
:: powershell.exe Set-Processmitigation -System -Enable DEP,CFG,ForceRelocateImages,BottomUp,SEHOP
::
:: Block executable files from running unless they meet a prevalence, age, or trusted list criterion
:: This one is commented out for now as I need to research and test more to determine potential impact
:: powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-cd74-433a-b99e-2ecdc07bfc25 -AttackSurfaceReductionRules_Actions Enabled
::
:: Enable Windows Defender real time monitoring
:: Commented out given consumers often run third party anti-virus. You can run either. 
:: powershell.exe -command "Set-MpPreference -DisableRealtimeMonitoring $false"
:: reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 0 /f
::
:: Disable internet connection sharing
:: Commented out as it's not enabled by default and if it is enabled, may be for a reason
:: reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections" /v NC_ShowSharedAccessUI /t REG_DWORD /d 0 /f
::
:: Always re-process Group Policy even if no changes
:: Commented out as consumers don't typically use GPO
:: reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" /v NoGPOListChanges /t REG_DWORD /d 0 /f
::
:: Force logoff if smart card removed
:: Set to "2" for logoff, set to "1" for lock
:: Commented out as consumers don't typically use smart cards
:: reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v SCRemoveOption /t REG_DWORD /d 2 /f
::
:: Restrict privileged local admin tokens being used from network 
:: Commented out as it only works on domain-joined assets
:: reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 0 /f
::
:: Ensure outgoing secure channel traffic is encrytped
:: Commented out as it only works on domain-joined assets
:: reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v RequireSignOrSeal /t REG_DWORD /d 1 /f
::
:: Enforce LDAP client signing
:: Commented out as most consumers don't use LDAP auth
:: reg add "HKLM\SYSTEM\CurrentControlSet\Services\LDAP" /v LDAPClientIntegrity /t REG_DWORD /d 1 /f
::
::#######################################################################
:: References
::#######################################################################
::
:: LLMNR
:: https://www.blackhillsinfosec.com/how-to-disable-llmnr-why-you-want-to/
:: 
:: Windows Defender References
:: ASR Rules https://www.darkoperator.com/blog/2017/11/11/windows-defender-exploit-guard-asr-rules-for-office
:: ASR and Exploit Guard https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-exploit-guard/attack-surface-reduction-exploit-guard
:: ASR Rules https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction
:: Easy methods to test rules https://demo.wd.microsoft.com/?ocid=cx-wddocs-testground
:: Resource on the rules and associated event IDs https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/event-views
:: Defender sandboxing https://cloudblogs.microsoft.com/microsoftsecure/2018/10/26/windows-defender-antivirus-can-now-run-in-a-sandbox/
:: Defender exploit protection https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-exploit-guard/customize-exploit-protection
:: Application Guard https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-guard/install-wd-app-guard 
:: Defender cmdline https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-antivirus/command-line-arguments-windows-defender-antivirus
::
:: General hardening references
:: LSA Protection https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn408187(v=ws.11)?redirectedfrom=MSDN
::
:: Microsoft Office References: 
:: Disable DDE https://gist.github.com/wdormann/732bb88d9b5dd5a66c9f1e1498f31a1b
:: Disable macros https://decentsecurity.com/block-office-macros/
::
:: Debloating
:: https://blog.danic.net/how-windows-10-pro-installs-unwanted-apps-candy-crush-and-how-you-stop-it/

:: Frameworks and benchmarks
:: STIG https://www.stigviewer.com/stig/windows_10/

````

awesome-windows-kernel-security-development


#### [windows-kernel-security-development](https://github.com/ExpLife0011/awesome-windows-kernel-security-development)




[shadowsocksr](https://github.com/shadowsocksrr/shadowsocksr)


Подымаем свой VPN и обходим блокировку сайтов (по Китайской технологии обход_Золотого_щита)

[FAKE CMD](https://github.com/Ondrik8/-Security/blob/master/cmd.exe) для хакеров! ;p

[attack_monitor](https://hakin9.org/attack-monitor-endpoint-detection-and-malware-analysis-software/)  мониторинг атак.

[Real Time Threat Monitoring](https://github.com/NaveenRudra/RTTM)

[BLUESPAWN](https://github.com/ION28/BLUESPAWN)

# Demo
![demo/ed.gif](https://raw.githubusercontent.com/yarox24/attack_monitor/master/demo/ed.gif)


[BZAR](https://github.com/mitre-attack/bzar) инструмент для обнаружение вторжений на основе данных mitre-attack

[Destroy Windows 10 Spying](https://github.com/Wohlstand/Destroy-Windows-10-Spying/releases)   Destroy Windows 10 Spying он отключает кейлоггеры, тех отчеты и блокирует IP адреса дяди Била.)

 [windows_hardening](https://github.com/0x6d69636b/windows_hardening) Это контрольный список для усиления защиты, который можно использовать в частных и бизнес-средах для защиты Windows 10. Контрольный список можно использовать для всех версий Windows, но в Windows 10 Home редактор групповой политики не интегрирован, и настройку необходимо выполнить непосредственно в реестр.
Параметры следует рассматривать как рекомендацию по безопасности и конфиденциальности, и их следует тщательно проверять, не повлияет ли они на работу вашей инфраструктуры или на удобство использования ключевых функций. Важно взвесить безопасность против юзабилити.
 

[reverse-vulnerabilities-software](https://www.apriorit.com/dev-blog/644-reverse-vulnerabilities-software-no-code-dynamic-fuzzing) Как обнаружить уязвимости в программном обеспечении, когда исходный код недоступен.




### IDS / IPS / Host IDS / Host IPS

- [Snort](https://www.snort.org/) - Snort - это бесплатная система с открытым исходным кодом для предотвращения вторжений (NIPS) и система обнаружения вторжений в сеть (NIDS), созданная Мартином Рошем в 1998 году. Snort в настоящее время разрабатывается. Sourcefire, основателем которого является Роеш и технический директор. В 2009 году Snort вошел в Зал Славы InfoWorld с открытым исходным кодом как одно из «величайших [образцов] программного обеспечения с открытым исходным кодом всех времен».
- [Bro](https://www.bro.org/) - Bro - это мощная инфраструктура сетевого анализа, которая сильно отличается от типичной IDS, которую вы, возможно, знаете.
- [OSSEC](https://ossec.github.io/) - Комплексная HIDS с открытым исходным кодом. Не для слабонервных. Требуется немного, чтобы понять, как это работает. Выполняет анализ журналов, проверку целостности файлов, мониторинг политик, обнаружение руткитов, оповещение в режиме реального времени и активный ответ. Он работает в большинстве операционных систем, включая Linux, MacOS, Solaris, HP-UX, AIX и Windows. Много разумной документации. Сладкое место - от среднего до крупного развертывания.
- [Suricata](http://suricata-ids.org/) - Suricata - это высокопроизводительный механизм мониторинга сетевых IDS, IPS и сетевой безопасности. Open Source и принадлежит общественному некоммерческому фонду Open Foundation Security Foundation (OISF). Suricata разработана OISF и его поставщиками.
- [Security Onion](http://blog.securityonion.net/) - Security Onion - это дистрибутив Linux для обнаружения вторжений, мониторинга сетевой безопасности и управления журналами. Он основан на Ubuntu и содержит Snort, Suricata, Bro, OSSEC, Sguil, Squert, Snorby, ELSA, Xplico, NetworkMiner и многие другие инструменты безопасности. Простой в использовании мастер установки позволяет создать целую армию распределенных датчиков для вашего предприятия за считанные минуты!
- [sshwatch](https://github.com/marshyski/sshwatch) - IPS для SSH аналогичен DenyHosts, написанному на Python. Он также может собирать информацию о злоумышленнике во время атаки в журнале.
- [Stealth](https://fbb-git.github.io/stealth/) - Проверка целостности файла, которая практически не оставляет осадка. Контроллер запускается с другого компьютера, что затрудняет злоумышленнику узнать, что файловая система проверяется через определенные псевдослучайные интервалы по SSH. Настоятельно рекомендуется для малых и средних развертываний.
- [AIEngine](https://bitbucket.org/camp0/aiengine) - AIEngine - это интерактивное / программируемое средство проверки пакетов Python / Ruby / Java / Lua следующего поколения с возможностями обучения без какого-либо вмешательства человека, NIDS (обнаружение вторжений в сеть) Системный) функционал, классификация доменов DNS, сетевой коллектор, криминалистика сети и многое другое.
- [Denyhosts](http://denyhosts.sourceforge.net/) - Помешать атакам на основе словаря SSH и атакам методом перебора.
- [Fail2Ban](http://www.fail2ban.org/wiki/index.php/Main_Page) - сканирует файлы журналов и выполняет действия по IP-адресам, которые показывают вредоносное поведение.
- [SSHGuard](http://www.sshguard.net/) - программное обеспечение для защиты служб в дополнение к SSH, написанное на C
- [Lynis](https://cisofy.com/lynis/) - инструмент аудита безопасности с открытым исходным кодом для Linux / Unix.

## Honey Pot / Honey Net

- [awesome-honeypots](https://github.com/paralax/awesome-honeypots) - Канонический список потрясающих приманок.
- [HoneyPy](https://github.com/foospidy/HoneyPy) - HoneyPy - это приманка с низким и средним уровнем взаимодействия. Он предназначен для простого развертывания, расширения функциональности с помощью плагинов и применения пользовательских конфигураций.
- [Dionaea](https://www.edgis-security.org/honeypot/dionaea/). Предполагается, что Dionaea станет преемником nepenthes, внедряет python в качестве языка сценариев, использует libemu для обнаружения шелл-кодов, поддерживает ipv6 и tls.
- [Conpot](http://conpot.org/) - ICS / SCADA Honeypot. Conpot - это приманка для систем промышленного управления с низким уровнем интерактивности на стороне сервера, разработанная для простого развертывания, изменения и расширения. Предоставляя ряд общих протоколов управления производством, мы создали основы для создания собственной системы, способной эмулировать сложные инфраструктуры, чтобы убедить противника в том, что он только что нашел огромный промышленный комплекс. Чтобы улучшить возможности обмана, мы также предоставили возможность сервера настраивать пользовательский интерфейс «человек-машина», чтобы увеличить поверхность атаки «приманок». Время отклика сервисов может быть искусственно задержано, чтобы имитировать поведение системы при постоянной нагрузке. Поскольку мы предоставляем полные стеки протоколов, к Conpot можно получить доступ с помощью производительных HMI или расширить с помощью реального оборудования.
- [Amun](https://github.com/zeroq/amun) - Honeypot с низким уровнем взаимодействия на основе Python.
- [Glastopf](http://glastopf.org/) - Glastopf - это Honeypot, который эмулирует тысячи уязвимостей для сбора данных от атак, направленных на веб-приложения. Принцип, лежащий в основе этого, очень прост: ответьте на правильный ответ злоумышленнику, использующему веб-приложение.
- [Kippo](https://github.com/desaster/kippo) - Kippo - это медпот SSH со средним взаимодействием, предназначенный для регистрации атак с использованием грубой силы и, что наиболее важно, всего взаимодействия с оболочкой, выполняемого атакующим.
- [Kojoney](http://kojoney.sourceforge.net/) - Kojoney - это приманка для взаимодействия низкого уровня, эмулирующая SSH-сервер. Демон написан на Python с использованием библиотек Twisted Conch.
- [HonSSH](https://github.com/tnich/honssh) - HonSSH - это решение Honey Pot с высоким уровнем взаимодействия. HonSSH будет находиться между атакующим и медом, создавая две отдельные SSH-связи между ними.
- [Bifrozt](http://sourceforge.net/projects/bifrozt/) - Bifrozt - это устройство NAT с сервером DHCP, которое обычно развертывается с одним NIC, подключенным напрямую к Интернету, и одним NIC, подключенным к внутренней сети. Что отличает Bifrozt от других стандартных устройств NAT, так это его способность работать в качестве прозрачного прокси-сервера SSHv2 между злоумышленником и вашей приманкой. Если вы развернете SSH-сервер во внутренней сети Bifrozt, он запишет все взаимодействия в файл TTY в виде простого текста, который можно будет просмотреть позже, и получит копию всех загруженных файлов. Вам не нужно устанавливать какое-либо дополнительное программное обеспечение, компилировать какие-либо модули ядра или использовать определенную версию или тип операционной системы на внутреннем сервере SSH, чтобы это работало.
- [HoneyDrive](http://bruteforce.gr/honeydrive) - HoneyDrive - это лучший Linux-дистрибутив honeypot. Это виртуальное устройство (OVA) с установленной версией Xubuntu Desktop 12.04.4 LTS. Он содержит более 10 предустановленных и предварительно настроенных пакетов программного обеспечения honeypot, таких как honeyppot Kippo SSH, honeypot с вредоносным ПО Dionaea и Amun, honeypot с низким уровнем взаимодействия Honeyd, honeypot и Wordpot Glastopf, Honeypot Conpot SCADA / ICS, honeyclients Thug и PhoneyC и многое другое. , Кроме того, он включает в себя множество полезных предварительно настроенных сценариев и утилит для анализа, визуализации и обработки данных, которые он может захватывать, таких как Kippo-Graph, Honeyd-Viz, DionaeaFR, стек ELK и многое другое. Наконец, в дистрибутиве также присутствует почти 90 известных инструментов анализа вредоносных программ, криминалистики и мониторинга сети.
- [Cuckoo Sandbox](http://www.cuckoosandbox.org/) - Cuckoo Sandbox - это программное обеспечение с открытым исходным кодом для автоматизации анализа подозрительных файлов. Для этого используются пользовательские компоненты, которые отслеживают поведение вредоносных процессов при работе в изолированной среде.
- [T-Pot Honeypot Distro](http://dtag-dev-sec.github.io/mediator/feature/2017/11/07/t-pot-17.10.html) - T-Pot основан на сети установщик Ubuntu Server 16 / 17.x LTS. Демоны honeypot, а также другие используемые компоненты поддержки были упакованы в контейнеры с помощью Docker. Это позволяет нам запускать несколько демонов honeypot в одном сетевом интерфейсе, сохраняя при этом небольшую площадь и ограничивая каждую honeypot в пределах собственной среды. Установка поверх стандартной Ubuntu - [T-Pot Autoinstall(https://github.com/dtag-dev-sec/t-pot-autoinstall) - Этот скрипт установит T-Pot 16.04 / 17.10 на свежую Ubuntu 16.04.x LTS (64 бита). Он предназначен для использования на хост-серверах, где указан базовый образ Ubuntu и нет возможности устанавливать собственные образы ISO. Успешно протестирован на ванильной Ubuntu 16.04.3 в VMware.

- База данных Honeypots
    - [Delilah](https://github.com/SecurityTW/delilah) - Elasticsearch Honeypot, написанный на Python (родом из Novetta).
    - [ESPot](https://github.com/mycert/ESPot) - Приманка Elasticsearch, написанная на NodeJS, чтобы фиксировать все попытки использования CVE-2014-3120.
    - [Эластичный мед](https://github.com/jordan-wright/elastichoney) - Простой Elasticsearch Honeypot.
    - [HoneyMysql](https://github.com/xiaoxiaoleo/HoneyMysql) - Простой проект Mysql honeypot.
    - [MongoDB-HoneyProxy](https://github.com/Plazmaz/MongoDB-HoneyProxy) - MongoDB-посредник-приманка.
    - [MongoDB-HoneyProxyPy](https://github.com/jwxa2015/MongoDB-HoneyProxyPy) - MongoDB-посредник-приманка от python3.
    - [NoSQLpot](https://github.com/torque59/nosqlpot) - платформа Honeypot, построенная на базе данных в стиле NoSQL.
    - [mysql-honeypotd](https://github.com/sjinks/mysql-honeypotd) - Приманка MySQL с низким уровнем взаимодействия, написанная на C.
    - [MysqlPot](https://github.com/schmalle/MysqlPot) - HoneySQL, еще очень ранняя стадия.
    - [pghoney](https://github.com/betheroot/pghoney) - Постгресский Honeypot с низким уровнем взаимодействия.
    - [sticky_elephant](https://github.com/betheroot/sticky_elephant) - средний постпосадочный honeypot.

- веб-приманки
    - [Bukkit Honeypot](https://github.com/Argomirr/Honeypot) - Плагин Honeypot для Bukkit.
    - [EoHoneypotBundle](https://github.com/eymengunay/EoHoneypotBundle) - тип Honeypot для форм Symfony2.
    - [Glastopf](https://github.com/mushorg/glastopf) - Honeypot веб-приложения.
    - [Google Hack Honeypot](http://ghh.sourceforge.net) - Предназначен для проведения разведки против злоумышленников, которые используют поисковые системы в качестве инструмента взлома ваших ресурсов.
    - [Laravel Application Honeypot](https://github.com/msurguy/Honeypot) - Простой пакет защиты от спама для приложений Laravel.
    - [Nodepot](https://github.com/schmalle/Nodepot) - Honeypot веб-приложения NodeJS.
    - [Servletpot](https://github.com/schmalle/servletpot) - веб-приложение Honeypot.
    - [Shadow Daemon](https://shadowd.zecure.org/overview/introduction/) - Модульный брандмауэр веб-приложений / Honeypot с высоким уровнем взаимодействия для приложений PHP, Perl и Python.
    - [StrutsHoneypot](https://github.com/Cymmetria/StrutsHoneypot) - Struts на основе Apache 2, а также модуль обнаружения для серверов Apache 2.
    - [WebTrap](https://github.com/IllusiveNetworks-Labs/WebTrap) - предназначен для создания обманчивых веб-страниц для обмана и перенаправления злоумышленников с реальных сайтов.
    - [basic-auth-pot (bap)](https://github.com/bjeborn/basic-auth-pot) - Honeypot базовой аутентификации HTTP.
    - [bwpot](https://github.com/graneed/bwpot) - Хрупкие веб-приложения honeyPot.
    - [django-admin-honeypot](https://github.com/dmpayton/django-admin-honeypot) - Поддельный экран входа администратора Django для уведомления администраторов о попытке несанкционированного доступа.
    - [drupo](https://github.com/d1str0/drupot) - Drupal Honeypot.
    - [honeyhttpd](https://github.com/bocajspear1/honeyhttpd) - построитель honeypot на основе Python для веб-сервера.
    - [phpmyadmin_honeypot](https://github.com/gfoss/phpmyadmin_honeypot) - простая и эффективная приманка phpMyAdmin.
    - [shockpot](https://github.com/threatstream/shockpot) - WebApp Honeypot для обнаружения попыток эксплойта Shell Shock.
    - [smart-honeypot](https://github.com/freak3dot/smart-honeypot) - PHP-скрипт, демонстрирующий умный горшок с медом.
    - Snare / Tanner - преемники Гластопфа
        - [Snare](https://github.com/mushorg/snare) - Супер-реактивная приманка следующего поколения Super.
        - [Tanner](https://github.com/mushorg/tanner) - Оценка событий SNARE.
    - [stack-honeypot](https://github.com/CHH/stack-honeypot) - вставляет ловушку для спам-ботов в ответы.
    - [tomcat-manager-honeypot](https://github.com/helospark/tomcat-manager-honeypot) - Honeypot, имитирующий конечные точки менеджера Tomcat. Регистрирует запросы и сохраняет файл WAR злоумышленника для дальнейшего изучения.
    - WordPress honeypot
        - [HonnyPotter](https://github.com/MartinIngesen/HonnyPotter) - Приманка для входа в WordPress для сбора и анализа неудачных попыток входа.
        - [HoneyPress](https://github.com/dustyfresh/HoneyPress) - HoneyPot на основе Python в контейнере Docker.
        - [wp-smart-honeypot](https://github.com/freak3dot/wp-smart-honeypot) - плагин WordPress для уменьшения спама в комментариях с более умной приманкой.
        - [wordpot](https://github.com/gbrindisi/wordpot) - WordPress Honeypot.

- Сервис Honeypots
    - [ADBHoney](https://github.com/huuck/ADBHoney) - Honeypot с низким уровнем взаимодействия, имитирующий устройство Android, на котором выполняется процесс сервера Android Debug Bridge (ADB). 
    - [AMTHoneypot](https://github.com/packetflare/amthoneypot) - Honeypot для уязвимости микропрограммы Intel для микропрограммы AMT, CVE-2017-5689.
    - [Ensnare](https://github.com/ahoernecke/ensnare) - Простая установка Ruby honeypot.
    - [HoneyPy](https://github.com/foospidy/HoneyPy) - Honeypot с низким уровнем взаимодействия.
    - [Honeygrove](https://github.com/UHH-ISS/honeygrove) - Многоцелевая модульная приманка на основе Twisted.
    - [Honeyport](https://github.com/securitygeneration/Honeyport) - Простой honeyport, написанный на Bash и Python.
    - [Honeyprint](https://github.com/glaslos/honeyprint) - Honeypot для принтера.
    - [Lyrebird](https://hub.docker.com/r/lyrebird/honeypot-base/) - Современный высокопроизводительный фреймворк honeypot.
    - [MICROS honeypot](https://github.com/Cymmetria/micros_honeypot) - Honeypot с низким уровнем взаимодействия для обнаружения CVE-2018-2636 в компоненте Oracle Hospitality Simphony в приложениях Oracle Hospitality Applications (MICROS).
    - [RDPy](https://github.com/citronneur/rdpy) - Honeypot протокола удаленного рабочего стола Microsoft (RDP), реализованный в Python.
    - [Приманка для малого и среднего бизнеса](https://github.com/r0hi7/HoneySMB) - Приманка для сервиса SMB с высоким уровнем взаимодействия, способная захватывать вредоносное ПО, похожее на странствующее.
    - [Tom's Honeypot](https://github.com/inguardians/toms_honeypot) - Сладкий Python honeypot.
    - [Приманка WebLogic](https://github.com/Cymmetria/weblogic_honeypot) - Приманка с низким уровнем взаимодействия для обнаружения CVE-2017-10271 в компоненте Oracle WebLogic Server Oracle Fusion Middleware.
    - [WhiteFace Honeypot](https://github.com/csirtgadgets/csirtg-honeypot) - витая приманка для WhiteFace.
    - [honeycomb_plugins](https://github.com/Cymmetria/honeycomb_plugins) - хранилище плагинов для Honeycomb, фреймворка honeypot от Cymmetria.
    - [honeyntp](https://github.com/fygrave/honeyntp) - NTP logger / honeypot.
    - [honeypot-camera](https://github.com/alexbredo/honeypot-camera) - Наблюдение за камерой honeypot.
    - [honeypot-ftp](https://github.com/alexbredo/honeypot-ftp) - FTP Honeypot.
    - [honeytrap](https://github.com/honeytrap/honeytrap) - расширенная среда Honeypot, написанная на Go, которая может быть связана с другим программным обеспечением honeypot.
    - [pyrdp](https://github.com/gosecure/pyrdp) - RDP man-in-the-middle и библиотека для Python 3 с возможностью наблюдения за соединениями в реальном времени или по факту.
    - [troje](https://github.com/dutchcoders/troje/) - Honeypot, который запускает каждое соединение со службой в отдельном контейнере LXC.

- Распределенные Honeypots
    - [DemonHunter](https://github.com/RevengeComing/DemonHunter) - Honeypot-сервер с низким уровнем взаимодействия.

- Анти-Honeypot вещи
    - [kippo_detect](https://github.com/andrew-morris/kippo_detect) - оскорбительный компонент, который обнаруживает присутствие приманки kippo.

- ICS / SCADA honeypots
    - [Conpot](https://github.com/mushorg/conpot) - Honeypot ICS / SCADA.
    - [GasPot](https://github.com/sjhilt/GasPot) - Veeder Root Gaurdian AST, распространенный в нефтегазовой промышленности.
    - [SCADA honeynet](http://scadahoneynet.sourceforge.net) - Создание Honeypots для промышленных сетей.
    - [gridpot](https://github.com/sk4ld/gridpot) - Инструменты с открытым исходным кодом для реалистичного поведения электрических сетей.
    - [scada-honeynet](http://www.digitalbond.com/blog/2007/07/24/scada-honeynet-article-in-infragard-publication/) - имитирует многие сервисы из популярного ПЛК и лучше помогает исследователям SCADA понять потенциальные риски, связанные с открытыми устройствами системы управления.

- Другое / случайное
    - [Чертовски простой Honeypot (DSHP)](https://github.com/naorlivne/dshp) - Каркас Honeypot с подключаемыми обработчиками.
    - [NOVA](https://github.com/DataSoft/Nova) - использует honeypots в качестве детекторов, выглядит как законченная система.
    - [OpenFlow Honeypot (OFPot)](https://github.com/upa/ofpot) - Перенаправляет трафик для неиспользуемых IP-адресов в honeypot, построенный на POX.
    - [OpenCanary](https://github.com/thinkst/opencanary) - Модульный и децентрализованный демон honeypot, который запускает несколько канарских версий сервисов и предупреждает, когда сервис (ab) используется.
    - [ciscoasa_honeypot](https://github.com/cymmetria/ciscoasa_honeypot) Honeypot с низким уровнем взаимодействия для компонента Cisco ASA, способного обнаруживать CVE-2018-0101, уязвимость DoS и удаленного выполнения кода. 
    - [miniprint](https://github.com/sa7mon/miniprint) - Honeypot принтера со средним взаимодействием.

- Ботнет C2 инструменты
    - [Hale](https://github.com/pjlantz/Hale) - Монитор управления и контроля ботнета.
    - [dnsMole](https://code.google.com/archive/p/dns-mole/) - анализирует трафик DNS и потенциально обнаруживает команды ботнета и контролирует активность сервера, а также зараженные хосты.

- средство обнаружения атак IPv6
    - [ipv6-атакующий детектор](https://github.com/mzweilin/ipv6-attack-detector/) - проект Google Summer of Code 2012, поддерживаемый организацией Honeynet Project.

- инструментарий динамического кода
    - [Frida](https://www.frida.re) - добавьте JavaScript для изучения нативных приложений на Windows, Mac, Linux, iOS и Android.

- Инструмент для конвертирования сайта в серверные приманки
    - [HIHAT](http://hihat.sourceforge.net/) - Преобразование произвольных приложений PHP в веб-интерфейсы Honeypots с высоким уровнем взаимодействия.

- сборщик вредоносных программ
    - [Kippo-Malware](https://bruteforcelab.com/kippo-malware) - скрипт Python, который загружает все вредоносные файлы, хранящиеся в виде URL-адресов в базе данных honeypot Kippo SSH.

- Распределенный датчик развертывания
    - [Modern Honey Network](https://github.com/threatstream/mhn) - Управление датчиками с множественным фырканьем и honeypot, использует сеть виртуальных машин, небольшие установки SNORT, скрытые дионеи и централизованный сервер для управления.

- Инструмент сетевого анализа
    - [Tracexploit](https://code.google.com/archive/p/tracexploit/) - воспроизведение сетевых пакетов.

- Журнал анонимайзера
    - [LogAnon](http://code.google.com/archive/p/loganon/) - Библиотека анонимной регистрации, которая помогает обеспечить согласованность анонимных журналов между журналами и захватами сети.

- Honeypot с низким уровнем взаимодействия (задняя дверь маршрутизатора)
    - [Honeypot-32764](https://github.com/knalli/honeypot-for-tcp-32764) - Honeypot для черного хода маршрутизатора (TCP 32764).
    - [WAPot](https://github.com/lcashdol/WAPot) - Honeypot, который можно использовать для наблюдения за трафиком, направленным на домашние маршрутизаторы.

- перенаправитель трафика фермы Honeynet
    - [Honeymole](https://web.archive.org/web/20100326040550/http://www.honeynet.org.pt:80/index.php/HoneyMole) - развертывание нескольких датчиков, которые перенаправляют трафик в централизованную коллекцию медовых горшков.

- HTTPS Proxy
    - [mitmproxy](https://mitmproxy.org/) - позволяет перехватывать, проверять, изменять и воспроизводить потоки трафика.

- Системная аппаратура
    - [Sysdig](https://sysdig.com/opensource/) - Исследование на уровне системы с открытым исходным кодом позволяет регистрировать состояние и активность системы из запущенного экземпляра GNU / Linux, а затем сохранять, фильтровать и анализировать результаты.
    - [Fibratus](https://github.com/rabbitstack/fibratus) - Инструмент для исследования и отслеживания ядра Windows.

- Honeypot для распространения вредоносного ПО через USB
    - [Ghost-usb](https://github.com/honeynet/ghost-usb-honeypot) - Honeypot для вредоносных программ, распространяющихся через запоминающие устройства USB.

- Сбор данных
    - [Kippo2MySQL](https://bruteforcelab.com/kippo2mysql) - извлекает некоторые очень простые статистические данные из текстовых файлов журналов Kippo и вставляет их в базу данных MySQL.
    - [Kippo2ElasticSearch](https://bruteforcelab.com/kippo2elasticsearch) - сценарий Python для передачи данных из базы данных MySQL Kippo SSH honeypot в экземпляр ElasticSearch (сервер или кластер).

- Парсер фреймворка пассивного сетевого аудита
    - [Инфраструктура пассивного сетевого аудита (pnaf)] (https://github.com/jusafing/pnaf) - платформа, которая объединяет несколько пассивных и автоматических методов анализа для обеспечения оценки безопасности сетевых платформ.

- VM мониторинг и инструменты
    - [Antivmdetect](https://github.com/nsmfoo/antivmdetection) - Скрипт для создания шаблонов для использования с VirtualBox, чтобы сделать обнаружение ВМ более сложным.
    - [VMCloak](https://github.com/hatching/vmcloak) - Автоматическое создание виртуальной машины и маскировка для песочницы с кукушкой.
    - [vmitools] (http://libvmi.com/) - библиотека C с привязками Python, которая позволяет легко отслеживать низкоуровневые детали работающей виртуальной машины.

- бинарный отладчик
    - [Hexgolems - серверная часть отладчика Pint](https://github.com/hexgolems/pint) - серверная часть отладчика и оболочка LUA для PIN-кода.
    - [Hexgolems - внешний интерфейс отладчика Schem](https://github.com/hexgolems/schem) - внешний интерфейс отладчика.

- Мобильный инструмент анализа
    - [Androguard](https://github.com/androguard/androguard) - Обратный инжиниринг, анализ вредоносных программ и программных продуктов для приложений Android и многое другое.
    - [APKinspector](https://github.com/honeynet/apkinspector/) - мощный инструмент с графическим интерфейсом для аналитиков для анализа приложений Android.

- Honeypot с низким уровнем взаимодействия
    - [Honeyperl](https://sourceforge.net/projects/honeyperl/) - Программное обеспечение Honeypot, основанное на Perl, с плагинами, разработанными для многих функций, таких как: wingates, telnet, squid, smtp и т. Д.
    - [T-Pot](https://github.com/dtag-dev-sec/tpotce) - Устройство «все в одном» от оператора связи T-Mobile

- Слияние данных Honeynet
    - [HFlow2](https://projects.honeynet.org/hflow) - инструмент объединения данных для анализа сети / медоносной сети.

- сервер
    - [Amun](http://amunhoney.sourceforge.net) - Honeypot эмуляции уязвимости.
    - [artillery](https://github.com/trustedsec/artillery/) - инструмент синей команды с открытым исходным кодом, предназначенный для защиты операционных систем Linux и Windows несколькими способами.
    - [Bait and Switch](http://baitnswitch.sourceforge.net) - перенаправляет весь враждебный трафик на honeypot, который частично отражает вашу производственную систему.
    - [HoneyWRT](https://github.com/CanadianJeff/honeywrt) - Приманка Python с низким уровнем взаимодействия, разработанная для имитации сервисов или портов, которые могут стать целью для злоумышленников.
    - [Honeyd](https://github.com/provos/honeyd) - См. [Honeyd tools] (# honeyd-tools).
    - [Honeysink](http://www.honeynet.org/node/773) - провал в сети с открытым исходным кодом, который обеспечивает механизм для обнаружения и предотвращения вредоносного трафика в данной сети.
    - [Hontel](https://github.com/stamparm/hontel) - Telnet Honeypot.
    - [KFSensor](http://www.keyfocus.net/kfsensor/) - Система обнаружения вторжений honeypot (IDS) на базе Windows.
    - [LaBrea](http://labrea.sourceforge.net/labrea-info.html) - захватывает неиспользуемые IP-адреса и создает виртуальные серверы, привлекательные для червей, хакеров и других пользователей Интернета.
    - [MTPot](https://github.com/Cymmetria/MTPot) - Telnet Honeypot с открытым исходным кодом, ориентированный на вредоносное ПО Mirai.
    - [SIREN](https://github.com/blaverick62/SIREN) - Полуинтеллектуальная сеть HoneyPot - Интеллектуальная виртуальная среда HoneyNet.
    - [TelnetHoney](https://github.com/balte/TelnetHoney) - Простая приманка telnet.
    - [UDPot Honeypot](https://github.com/jekil/UDPot) - Простые сценарии UDP / DNS honeypot.
    - [Еще одна поддельная приманка (YAFH)](https://github.com/fnzv/YAFH) - Простая приманка, написанная на Go.
    - [арктическая ласточка](https://github.com/ajackal/arctic-swallow) - Honeypot с низким уровнем взаимодействия.
    - [обжора](https://github.com/mushorg/glutton) - Все едят honeypot.
    - [go-HoneyPot](https://github.com/Mojachieee/go-HoneyPot) - сервер Honeypot, написанный на Go.
    - [go-emulators](https://github.com/kingtuna/go-emulators) - Эмуляторы Honeypot Golang.
    - [honeymail](https://github.com/sec51/honeymail) - приманка SMTP, написанная на Голанге.
    - [honeytrap](https://github.com/tillmannw/honeytrap) - Honeypot с низким уровнем взаимодействия и инструмент сетевой безопасности, написанный для ловли атак на службы TCP и UDP.
    - [imap-honey](https://github.com/yvesago/imap-honey) - приманка IMAP, написанная на Голанге.
    - [mwcollectd](https://www.openhub.net/p/mwcollectd) - универсальный демон сбора вредоносных программ, объединяющий в себе лучшие функции nepenthes и honeytrap.
    - [potd](https://github.com/lnslbrty/potd) - Высоко масштабируемая приманка SSH / TCP с низким и средним взаимодействием, разработанная для устройств OpenWrt / IoT, использующая несколько функций ядра Linux, таких как пространства имен, seccomp и возможности потоков ,
    - [portlurker](https://github.com/bartnv/portlurker) - прослушиватель портов в Rust с угадыванием протокола и безопасным отображением строк.
    - [slipm-honeypot](https://github.com/rshipp/slipm-honeypot) - Простой honeypot для мониторинга портов с низким уровнем взаимодействия.
    - [telnet-iot-honeypot](https://github.com/Phype/telnet-iot-honeypot) - Python telnet honeypot для ловли двоичных файлов ботнетов.
    - [telnetlogger](https://github.com/robertdavidgraham/telnetlogger) - приманка Telnet, предназначенная для отслеживания ботнета Mirai.
    - [vnclowpot](https://github.com/magisterquis/vnclowpot) - Honeypot с низким уровнем взаимодействия VNC.


- Генерация подписи IDS
    - [Honeycomb](http://www.icir.org/christian/honeycomb/) - Автоматическое создание подписи с использованием honeypots.

- Служба поиска номеров и префиксов AS
    - [CC2ASN](http://www.cc2asn.com/) - Простой сервис поиска номеров AS и префиксов, принадлежащих любой стране мира.

- Сбор данных / обмен данными
    - [HPfriends](http://hpfriends.honeycloud.net/#/home) - Платформа обмена данными Honeypot.
        - [hpfriends - обмен социальными данными в режиме реального времени](https://heipei.io/sigint-hpfriends/) - Презентация о системе подачи HPFriends 
    - [HPFeeds](https://github.com/rep/hpfeeds/) - Легкий аутентифицированный протокол публикации-подписки.

- Центральный инструмент управления
    - [PHARM](http://www.nepenthespharm.com/) - Управляйте, сообщайте и анализируйте свои распределенные экземпляры Nepenthes.

- Анализатор сетевого подключения
    - [Impost](http://impost.sourceforge.net/) - инструмент аудита сетевой безопасности, предназначенный для анализа криминалистических данных за скомпрометированными и / или уязвимыми демонами. 

- Развертывание Honeypot
    - [Современная сеть Honeynet](http://threatstream.github.io/mhn/) - Оптимизирует развертывание и управление безопасными honeypots.

- Расширения Honeypot для Wireshark
    - [Расширения Whireshark](https://www.honeynet.org/project/WiresharkExtensions) - Применение правил и подписей Snort IDS к файлам захвата пакетов с помощью Wireshark.


- Клиент
    - [CWSandbox / GFI Sandbox](https://www.gfi.com/products-and-solutions/all-products)
    - [Capture-HPC-Linux](https://redmine.honeynet.org/projects/linux-capture-hpc/wiki)
    - [Capture-HPC-NG](https://github.com/CERT-Polska/HSN-Capture-HPC-NG)
    - [Capture-HPC](https://projects.honeynet.org/capture-hpc) - Honeypot клиента с высоким уровнем взаимодействия (также называемый honeyclient).
    - [HoneyBOT](http://www.atomicsoftwaresolutions.com/)
    - [HoneyC](https://projects.honeynet.org/honeyc)
    - [HoneySpider Network](https://github.com/CERT-Polska/hsn2-bundle) - Высоко масштабируемая система, объединяющая несколько клиентских приманок для обнаружения вредоносных веб-сайтов.
    - [HoneyWeb](https://code.google.com/archive/p/gsoc-honeyweb/) - веб-интерфейс, созданный для управления и удаленного обмена ресурсами Honeyclients. 
    - [Jsunpack-n](https://github.com/urule99/jsunpack-n)
    - [MonkeySpider](http://monkeyspider.sourceforge.net)
    - [PhoneyC](https://github.com/honeynet/phoneyc) - медленный клиент Python (позже замененный Thug).
    - [Pwnypot](https://github.com/shjalayeri/pwnypot) - Honeypot клиента с высоким уровнем взаимодействия.
    - [Rumal](https://github.com/thugs-rumal/) - Rumāl Thug's: платье и оружие Thug's.
    - [shelia](https://www.cs.vu.nl/~herbertb/misc/shelia/) - Приманка на стороне клиента для обнаружения атак.
    - [Thug] (https://buffer.github.io/thug/) - медленный клиент с низким уровнем взаимодействия на основе Python.
    - [Очередь распределенных задач Thug](https://thug-distributed.readthedocs.io/en/latest/index.html)
    - [Тригона](https://www.honeynet.org/project/Trigona)
    - [URLQuery](https://urlquery.net/)
    - [YALIH (еще один медленный клиент с низким уровнем взаимодействия)](https://github.com/Masood-M/yalih) - приманка для клиентов с низким уровнем взаимодействия, предназначенная для обнаружения вредоносных веб-сайтов с помощью методов подписи, аномалий и сопоставления с образцом.

- Горшок меда
    - [Инструмент обмана](http://www.all.net/dtk/dtk.html)
    - [IMHoneypot](https://github.com/mushorg/imhoneypot)

- PDF документ инспектор
    - [peepdf](https://github.com/jesparza/peepdf) - Мощный инструмент Python для анализа PDF-документов.

- Гибридная приманка с низким / высоким взаимодействием
    - [HoneyBrid](http://honeybrid.sourceforge.net)

- SSH Honeypots
    - [Blacknet](https://github.com/morian/blacknet) - Система с несколькими головками SSH honeypot.
    - [Cowrie](https://github.com/cowrie/cowrie) - Cowrie SSH Honeypot (на основе kippo).
    - [Докер DShield](https://github.com/xme/dshield-docker) - Контейнер Docker, на котором запущена задатка с включенным выводом DShield.
    - [HonSSH](https://github.com/tnich/honssh) - регистрирует все соединения SSH между клиентом и сервером.
    - [HUDINX](https://github.com/Cryptix720/HUDINX) - Крошечное взаимодействие SSH-приманка, разработанная в Python для регистрации атак методом перебора и, что наиболее важно, всего взаимодействия с оболочкой, выполняемого атакующим.
    - [Kippo](https://github.com/desaster/kippo) - Приманка SSH со средним взаимодействием.
    - [Kippo_JunOS](https://github.com/gregcmartin/Kippo_JunOS) - Kippo настроен как задний экран.
    - [Kojoney2](https://github.com/madirish/kojoney2) - Honeypot с низким уровнем взаимодействия SSH, написанный на Python и основанный на коджени Хосе Антонио Коретом.
    - [Kojoney](http://kojoney.sourceforge.net/) - Honeypot с низким уровнем взаимодействия на основе Python, эмулирующий SSH-сервер, реализованный с помощью Twisted Conch.
    - [Анализ логов LongTail @ Marist College](http://longtail.it.marist.edu/honey/) - Анализ логов SSH приманки.
    - [Malbait](https://github.com/batchmcnulty/Malbait) - Простая приманка TCP / UDP, реализованная в Perl.
    - [MockSSH](https://github.com/ncouture/MockSSH) - Создайте макет сервера SSH и определите все команды, которые он поддерживает (Python, Twisted).
    - [cowrie2neo](https://github.com/xlfe/cowrie2neo) - анализировать журналы honeypot cowrie в базе данных neo4j.
    - [go-sshoney](https://github.com/ashmckenzie/go-sshoney) - Honeypot SSH.
    - [go0r](https://github.com/fzerorubigd/go0r) - Простая ssh honeypot на Голанге.
    - [gohoney](https://github.com/PaulMaddox/gohoney) - приманка SSH, написанная на Go.
    - [hived](https://github.com/sahilm/hived) - Honeypot на основе Голанга.
    - [hnypots-agent)](https://github.com/joshrendek/hnypots-agent) - SSH-сервер в Go, который регистрирует комбинации имени пользователя и пароля.
    - [honeypot.go](https://github.com/mdp/honeypot.go) - Honeypot SSH, написанный на Go.
    - [honeyssh](https://github.com/ppacher/honeyssh) - учетная запись сброса приманки SSH со статистикой.
    - [hornet](https://github.com/czardoz/hornet) - Приманка среднего уровня SSH, поддерживающая несколько виртуальных хостов.
    - [ssh-auth-logger](https://github.com/JustinAzoff/ssh-auth-logger) - Honeypot ведения журнала аутентификации SSH с низким / нулевым взаимодействием.
    - [ssh-honeypot](https://github.com/droberson/ssh-honeypot) - Поддельный sshd, который регистрирует IP-адреса, имена пользователей и пароли.
    - [ssh-honeypot](https://github.com/amv42/sshd-honeypot) - модифицированная версия демона OpenSSH, который перенаправляет команды в Cowrie, где все команды интерпретируются и возвращаются.
    - [ssh-honeypotd](https://github.com/sjinks/ssh-honeypotd) - Honeypot с низким уровнем взаимодействия SSH, написанный на C.
    - [sshForShits](https://github.com/traetox/sshForShits) - Фреймворк для высокопроизводительного SSH-приманки.
    - [sshesame](https://github.com/jaksi/sshesame) - фальшивый SSH-сервер, который позволяет всем входить и регистрировать свою активность.
    - [sshhipot](https://github.com/magisterquis/sshhipot) - Приманка MitM SSH с высокой степенью взаимодействия.
    - [sshlowpot](https://github.com/magisterquis/sshlowpot) - Еще один не требующий излишеств приманки SSH с низким уровнем взаимодействия в Go.
    - [sshsyrup](https://github.com/mkishere/sshsyrup) - Простой SSH Honeypot с функциями для захвата активности терминала и загрузки на asciinema.org.
    - [витые приманки](https://github.com/lanjelot/twisted-honeypots) - приманки SSH, FTP и Telnet на основе Twisted.

- Распределенный датчик проекта
    - [Проект DShield Web Honeypot](https://sites.google.com/site/webhoneypotsite/)

- анализатор pcap
    - [Honeysnap](https://projects.honeynet.org/honeysnap/)

- Перенаправитель сетевого трафика
    - [Honeywall](https://projects.honeynet.org/honeywall/)

- Honeypot Distribution со смешанным содержимым
    - [HoneyDrive](https://bruteforcelab.com/honeydrive)

- Датчик Honeypot
    - [Honeeepi](https://redmine.honeynet.org/projects/honeeepi/wiki) - Датчик Honeypot на Raspberry Pi на основе настроенной Raspbian OS.

- Резьба по файлу
    - [TestDisk & PhotoRec](https://www.cgsecurity.org/)

- Инструмент поведенческого анализа для win32
    - [Capture BAT](https://www.honeynet.org/node/315)

- Live CD
    - [DAVIX](https://www.secviz.org/node/89) - DAVIX Live CD.

- Spamtrap
    - [Mail :: SMTP :: Honeypot](https://metacpan.org/pod/release/MIKER/Mail-SMTP-Honeypot-0.11/Honeypot.pm) - модуль Perl, обеспечивающий функциональность стандартного SMTP сервер.
    - [Mailoney](https://github.com/awhitehatter/mailoney) - SMTP honeypot, Open Relay, Cred Harvester, написанный на python.
    - [SendMeSpamIDS.py](https://github.com/johestephan/VerySimpleHoneypot) - Простой SMTP-выбор всех IDS и анализатора.
    - [Шива](https://github.com/shiva-spampot/shiva) - Спам Honeypot с интеллектуальным виртуальным анализатором.
        - [Шива Советы и хитрости по борьбе со спамом для его запуска и работы] (https://www.pentestpartners.com/security-blog/shiva-the-spam-honeypot-tips-and-tricks-for-getting-it -up-и-запуск /)
    - [SpamHAT](https://github.com/miguelraulb/spamhat) - Инструмент для борьбы со спамом.
    - [Spamhole](http://www.spamhole.net/)
    - [honeypot](https://github.com/jadb/honeypot) - Неофициальный PHP SDK проекта Honey Pot.
    - [spamd](http://man.openbsd.org/cgi-bin/man.cgi?query=spamd%26apropos=0%26sektion=0%26manpath=OpenBSD+Current%26arch=i386%26format=html)

- Коммерческая HONEY сеть
    - [Cymmetria Mazerunner](https://cymmetria.com/products/mazerunner/) - отводит злоумышленников от реальных целей и создает след атаки.

## Руководства

- [T-Pot: платформа для нескольких приманок](https://dtag-dev-sec.github.io/mediator/feature/2015/03/17/concept.html)
- [Сценарий установки Honeypot (Dionaea и kippo)](https://github.com/andrewmichaelsmith/honeypot-setup-script/)

- Развертывание
    - [Dionaea и EC2 за 20 минут](http://andrewmichaelsmith.com/2012/03/dionaea-honeypot-on-ec2-in-20-minutes/) - Учебное пособие по настройке Dionaea в экземпляре EC2.
    - [Использование приманки Raspberry Pi для передачи данных в DShield / ISC] (https://isc.sans.edu/diary/22680) - Система на основе Raspberry Pi позволит нам поддерживать одну кодовую базу, которая упростит собирать расширенные журналы за пределами журналов брандмауэра.
    - [honeypotpi](https://github.com/free5ty1e/honeypotpi) - Скрипт для превращения Raspberry Pi в HoneyPot Pi.

- Научно-исследовательские работы
    - [Исследовательские работы Honeypot](https://github.com/shbhmsingh72/Honeypot-Research-Papers) - PDF-файлы исследовательских работ по honeypots.
    - [vEYE](https://link.springer.com/article/10.1007%2Fs10115-008-0137-3) - Поведенческие следы для самораспространяющегося обнаружения и профилирования червя.
