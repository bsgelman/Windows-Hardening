if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
 if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
  $CommandLine = "-File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
  Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
  Exit
 }
}


Set-ExecutionPolicy -ExecutionPolicy Unrestricted


#################################################
##                                             ##
##           Windows Hardening Script          ##
##          Written by: Ben Gelman             ##
##                                             ##
#################################################


#WHAT TO SEARCH FOR WHEN EDITING SCRIPT FOR CRITICAL SERVICES
#TlntSvr ; Telnet = telnet
#Msftpsvc ; FTP= microsoft ftp 
#ftpsvc ; FTP = ftp
#Smtpsvc ; SMTP = SMTP service
#Termservice ; RDP = remote desktop

$ErrorActionPreference = 'silentlycontinue'

set mypath=%~dp0

mkdir C:\ComCorp

Write-Host Enabling system restore... -ForegroundColor Yellow -BackgroundColor Black
Reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v DisableSR /t REG_DWORD /d 0 /f
sc.exe config srservice start= Auto
net start srservice
sc.exe config VSS start= auto



Write-Host Listing initial service configurations... -ForegroundColor Yellow -BackgroundColor Black
sc.exe query >> C:\ComCorp\Services_Original.txt



Write-Host Listing possible penetrations... -ForegroundColor Yellow -BackgroundColor Black
Write-Host STARTING TO OUTPUT FILES DIRECTLY TO C:\ComCorp\ -ForegroundColor Yellow -BackgroundColor Black
wmic process list brief > C:\ComCorp\BriefProcesses.txt
wmic process list full > C:\ComCorp\FullProcesses.txt
wmic startup list full > C:\ComCorp\StartupLists.txt
net start > C:\ComCorp\StartedProcesses.txt
reg export HKLM\Software\Microsoft\Windows\CurrentVersion\Run  Run.reg


Write-Host Grabbing files and organizing them... -ForegroundColor Yellow -BackgroundColor Black
New-Item -Path C:\Comcorp\userfiles -ItemType directory
New-Item -Path C:\Comcorp\programfiles -ItemType directory
New-Item -Path C:\Comcorp\programfilesx86 -ItemType directory
New-Item -Path C:\Comcorp\documents -ItemType directory

Write-Host Grabbing User Files... -ForegroundColor Yellow -BackgroundColor Black
Get-ChildItem -Path "C:\Users\*" -Include *.jpg,*.png,*.aac,*.ac3,*.avi,*.aiff,*.bat,*.bmp,*.exe,*.flac,*.gif,*.jpeg,*.mov,*.m3u,*.m4p,*.mp2,*.mp3,*.mp4,*.mpeg4,*.midi,*.msi,*.ogg,*.png,*.txt,*.sh,*.wav,*.wma,*.vqf,*.pcap,*.zip,*.pdf,*.json -Recurse | Copy-Item -Destination C:\ComCorp\userfiles

Write-Host Grabbing Program Files... -ForegroundColor Yellow -BackgroundColor Black
Get-ChildItem -Path "C:\Program Files\*" -Include *.jpg,*.png,*.aac,*.ac3,*.avi,*.aiff,*.bat,*.bmp,*.exe,*.flac,*.gif,*.jpeg,*.mov,*.m3u,*.m4p,*.mp2,*.mp3,*.mp4,*.mpeg4,*.midi,*.msi,*.ogg,*.png,*.txt,*.sh,*.wav,*.wma,*.vqf,*.pcap,*.zip,*.pdf,*.json -Recurse | Copy-Item -Destination C:\ComCorp\programfiles
Get-ChildItem -Path "C:\Program Files (x86)\*" -Include *.jpg,*.png,*.aac,*.ac3,*.avi,*.aiff,*.bat,*.bmp,*.exe,*.flac,*.gif,*.jpeg,*.mov,*.m3u,*.m4p,*.mp2,*.mp3,*.mp4,*.mpeg4,*.midi,*.msi,*.ogg,*.png,*.txt,*.sh,*.wav,*.wma,*.vqf,*.pcap,*.zip,*.pdf,*.json -Recurse | Copy-Item -Destination C:\ComCorp\programfilesx86

Write-Host Grabbing Documents... -ForegroundColor Yellow -BackgroundColor Black
Get-ChildItem -Path "~\Documents\*" -Include *.jpg,*.png,*.aac,*.ac3,*.avi,*.aiff,*.bat,*.bmp,*.exe,*.flac,*.gif,*.jpeg,*.mov,*.m3u,*.m4p,*.mp2,*.mp3,*.mp4,*.mpeg4,*.midi,*.msi,*.ogg,*.png,*.txt,*.sh,*.wav,*.wma,*.vqf,*.pcap,*.zip,*.pdf,*.json -Recurse | Copy-Item -Destination C:\ComCorp\documents

Write-Host Grabbing Media Files... -ForegroundColor Yellow -BackgroundColor Black
Get-ChildItem -Path "C:\Users" -Include *.jpg,*.png,*.jpeg,*.avi,*.mp4,*.mp3,*.wav,*.m4v,*.mov -Exclude .dll,.doc,*.docx,  -File -Recurse -ErrorAction SilentlyContinue | Out-File -filepath C:\ComCorp\Mediafiles.txt

Write-Host Grabbing Hosts File... -ForegroundColor Yellow -BackgroundColor Black
New-Item -Path C:\ComCorp\hosts -ItemType directory
Get-ChildItem -Path "C:\Windows\System32\drivers\etc\hosts" | Copy-Item -Destination C:\ComCorp\hosts

Write-Host Listing processes that have bigger loads... -ForegroundColor Yellow -BackgroundColor Black
Get-Process | Where-Object {$_.WorkingSet -gt 20000000} > C:\ComCorp\interestingprocess.txt 

Write-Host Listing Scheduled Tasks... -ForegroundColor Yellow -BackgroundColor Black
Get-ScheduledTask | where state -EQ 'ready' | Get-ScheduledTaskInfo | 
Export-Csv -NoTypeInformation -Path C:\ComCorp\scheduledTasksResults.csv

Write-Host Listing users, groups, and shares... -ForegroundColor Yellow -BackgroundColor Black
net user > C:\ComCorp\users.txt
net localgroup > C:\ComCorp\groups.txt
net share > C:\ComCorp\shares.txt

Write-Host Backing up Original Firewall Policy... -ForegroundColor Yellow -BackgroundColor Black
netsh advfirewall export "C:\ComCorp\Original_Firewall_Policy.wfw"

Write-Host Listing currently running services... -ForegroundColor Yellow -BackgroundColor Black
net start >> C:\ComCorp\Services_Started.txt

Write-Host Enabling Windows God Mode... -ForegroundColor Yellow -BackgroundColor Black
$godmodeSplat = @{
Path = "$env:USERPROFILE\Desktop"
Name = "GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}"
ItemType = 'Directory'
}
New-Item @godmodeSplat


#################################################

function select_func(){
    $option = Read-Host '

1. Harden Networking
2. Harden Windows Defender
3. Disable Remote Desktop
4. Configure Registry
5. Configure Services
6. Disabling SMB1
7. Audit Policies
8. Bulk Password Change
9. Set Up Backup
10. Update Powershell
11. Download SysInternals
12. Download AVG antivirus
13. Download Malwarebytes Anti-Malware
14. Flush DNS Cache
15. Configure Windows Features
16. Configure Internet Explorer
17. Disable NetBIOS
18. Delete Media Files
19. Harden Google Chrome
20. Run System File Checker
Enter your choice'

#################################################



if ($option -eq 1) {
    
    Write-Host Enabling windows firewall... -ForegroundColor Yellow -BackgroundColor Black

    Write-Host "Turning the firewall on..." -ForegroundColor Yellow -BackgroundColor Black
    netsh advfirewall set currentprofile state on

    Write-Host "Turning all states on the firewall on..." -ForegroundColor Yellow -BackgroundColor Black
    netsh advfirewall set currentprofile set allprofile state on

    Write-Host "Setting Firewall Log MaxFileSize to 4096..." -ForegroundColor Yellow -BackgroundColor Black
    netsh advfirewall set allprofile logging maxfilesize 4096

    Write-Host "Setting Firewall Log to log DROPPED connections..." -ForegroundColor Yellow -BackgroundColor Black
    netsh advfirewall set allprofile logging droppedconnections enable

    Write-Host "Setting Firewall Log to log ALLOWED connections..." -ForegroundColor Yellow -BackgroundColor Black
    netsh advfirewall set allprofile logging allowedconnections enable

    Write-Host "Disabling IPv6..." -ForegroundColor Yellow -BackgroundColor Black
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name 'DisabledComponents' -Value '0xFF' -Type 'Dword'
    Disable-NetAdapterBinding -Name '*' -ComponentID 'ms_tcpip6'
    New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Services\tcpip6\Parameters" -name DisabledComponents -value 0xff
    reg add "HKLM\System\CurrentControlSet\services\TCPIP6\Parameters" /v DisabledComponents /t REG_DWORD /d 255 /f

    Write-Host "Disabling Remote Assistance" -ForegroundColor Yellow -BackgroundColor Black
    netsh advfirewall firewall set rule group="Remote Assistance" new enable=no

    Write-Host "Setting IPv4 as a priority for communication" -ForegroundColor Yellow -BackgroundColor Black
    netsh interface ipv6 set prefixpolicy ::ffff:0:0/96 46 4

    sc.exe config MPSSVC start= auto
    net start MPSSVC

    #Disable SSL v2
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Force
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client"-Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Force -Name Enabled -Type "DWORD" -Value 0
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Force -Name DisabledByDefault -Type "DWORD" -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" -Force -Name Enabled -Type "DWORD" -Value 0
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" -Force -Name DisabledByDefault -Type "DWORD" -Value 1

    #Disable SSL v3
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server"-Force
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Force -Name Enabled -Type "DWORD" -Value 0
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Force -Name DisabledByDefault -Type "DWORD" -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -Force -Name Enabled -Type "DWORD" -Value 0
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -Force -Name DisabledByDefault -Type "DWORD" -Value 1

    #Enable TLS 1.0
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Force
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Force -Name Enabled -Type "DWORD" -Value 0x00000000
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Force -Name DisabledByDefault -Type "DWORD" -Value 0x00000001
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Force -Name Enabled -Type "DWORD" -Value 0x00000000
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Force -Name DisabledByDefault -Type "DWORD" -Value 0x00000001

    #Enable DTLS 1.0
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Server" -Force
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Client" -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Server" -Force -Name Enabled -Type "DWORD" -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Server" -Force -Name DisabledByDefault -Type "DWORD" -Value 0
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Client" -Force -Name Enabled -Type "DWORD" -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Client" -Force -Name DisabledByDefault -Type "DWORD" -Value 0

    #Enable TLS 1.1
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Force
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Force -Name Enabled -Type "DWORD" -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Force -Name DisabledByDefault -Type "DWORD" -Value 0
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Force -Name Enabled -Type "DWORD" -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Force -Name DisabledByDefault -Type "DWORD" -Value 0

    #Enable DTLS 1.1
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.1\Server" -Force
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.1\Client" -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.1\Server" -Force -Name Enabled -Type "DWORD" -Value 0
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.1\Server" -Force -Name DisabledByDefault -Type "DWORD" -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.1\Client" -Force -Name Enabled -Type "DWORD" -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.1\Client" -Force -Name DisabledByDefault -Type "DWORD" -Value 0

    #Enable TLS 1.2
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Force
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Force -Name Enabled -Type "DWORD" -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Force -Name DisabledByDefault -Type "DWORD" -Value 0
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Force -Name Enabled -Type "DWORD" -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Force -Name DisabledByDefault -Type "DWORD" -Value 0

    #Enable TLS 1.3
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" -Force
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" -Force -Name Enabled -Type "DWORD" -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" -Force -Name DisabledByDefault -Type "DWORD" -Value 0
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" -Force -Name Enabled -Type "DWORD" -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" -Force -Name DisabledByDefault -Type "DWORD" -Value 0

    #Enable DTLS 1.3
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.3\Server" -Force
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.3\Client" -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.3\Server" -Force -Name Enabled -Type "DWORD" -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.3\Server" -Force -Name DisabledByDefault -Type "DWORD" -Value 0
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.3\Client" -Force -Name Enabled -Type "DWORD" -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.3\Client" -Force -Name DisabledByDefault -Type "DWORD" -Value 0

    #Enable Strong Authentication for .NET applications (TLS 1.2)
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" -Force -Name SchUseStrongCrypto -Type "DWORD" -Value 0x00000001
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" -Force -Name SystemDefaultTlsVersions -Type "DWORD" -Value 0x00000001
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v3.0" -Force -Name SchUseStrongCrypto -Type "DWORD" -Value 0x00000001
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v3.0" -Force -Name SystemDefaultTlsVersions -Type "DWORD" -Value 0x00000001
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Force -Name SchUseStrongCrypto -Type "DWORD" -Value 0x00000001
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Force -Name SystemDefaultTlsVersions -Type "DWORD" -Value 0x00000001
    Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727" -Force -Name SchUseStrongCrypto -Type "DWORD" -Value 0x00000001
    Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727" -Force -Name SystemDefaultTlsVersions -Type "DWORD" -Value 0x00000001
    Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v3.0" -Force -Name SchUseStrongCrypto -Type "DWORD" -Value 0x00000001
    Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v3.0" -Force -Name SystemDefaultTlsVersions -Type "DWORD" -Value 0x00000001
    Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319" -Force -Name SchUseStrongCrypto -Type "DWORD" -Value 0x00000001
    Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319" -Force -Name SystemDefaultTlsVersions -Type "DWORD" -Value 0x00000001

    netsh Advfirewall set allprofiles state on
    netsh advfirewall set publicprofile state on
    netsh advfirewall set domainprofile state on
    netsh advfirewall set publicprofile state on
    netsh advfirewall set privateprofile state on
    netsh advfirewall set currentprofile logging maxfilesize 4096
    netsh advfirewall set currentprofile logging droppedconnections enable
    netsh advfirewall set currentprofile logging allowedconnections enable
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
    Set-NetFirewallProfile -DefaultInboundAction Block -DefaultOutboundAction Allow -NotifyOnListen True -AllowUnicastResponseToMulticast True -LogFileName %SystemRoot%\System32\LogFiles\Firewall\pfirewall.log
    netsh advfirewall firewall set rule name="Remote Assistance (DCOM-In)" new enable=no
    netsh advfirewall firewall set rule name="Remote Assistance (PNRP-In)" new enable=no 
    netsh advfirewall firewall set rule name="Remote Assistance (RA Server TCP-In)" new enable=no
    netsh advfirewall firewall set rule name="Remote Assistance (SSDP TCP-In)" new enable=no
    netsh advfirewall firewall set rule name="Remote Assistance (SSDP UDP-In)" new enable=no
    netsh advfirewall firewall set rule name="Remote Assistance (TCP-In)" new enable=no
    netsh advfirewall firewall set rule name="Telnet Server" new enable=no 
    netsh advfirewall firewall set rule name="netcat" new enable=no
    netsh advfirewall firewall set rule group="Network Discovery" new enable=No
    netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=No
    netsh advfirewall firewall add rule name="block_RemoteRegistry_in" dir=in service="RemoteRegistry" action=block enable=yes
    netsh advfirewall firewall add rule name="block_RemoteRegistry_out" dir=out service="RemoteRegistry" action=block enable=yes
    New-NetFirewallRule -DisplayName "Block Outbound Port 21" -Direction Inbound -LocalPort 21 -Protocol TCP -Action Block
    New-NetFirewallRule -DisplayName "Block Outbound Port 22" -Direction Inbound -LocalPort 22 -Protocol TCP -Action Block
    New-NetFirewallRule -DisplayName "Block Outbound Port 23" -Direction Inbound -LocalPort 23 -Protocol TCP -Action Block
    New-NetFirewallRule -DisplayName "Block Outbound Port 25" -Direction Inbound -LocalPort 25 -Protocol TCP -Action Block
    New-NetFirewallRule -DisplayName "Block Outbound Port 80" -Direction Inbound -LocalPort 80 -Protocol TCP -Action Block
    New-NetFirewallRule -DisplayName "Block Outbound Port 161" -Direction Inbound -LocalPort 161 -Protocol TCP -Action Block
    New-NetFirewallRule -DisplayName "Block Outbound Port 162" -Direction Inbound -LocalPort 162 -Protocol TCP -Action Block
    New-NetFirewallRule -DisplayName "Block Outbound Port 3389" -Direction Inbound -LocalPort 3389 -Protocol TCP -Action Block
    New-NetFirewallRule -DisplayName "Block Outbound Port 4444" -Direction Inbound -LocalPort 4444 -Protocol TCP -Action Block
    New-NetFirewallRule -DisplayName "Block Outbound Port 8080" -Direction Inbound -LocalPort 8080 -Protocol TCP -Action Block
    New-NetFirewallRule -DisplayName "Block Outbound Port 8088" -Direction Inbound -LocalPort 8088 -Protocol TCP -Action Block
    New-NetFirewallRule -DisplayName "Block Outbound Port 8888" -Direction Inbound -LocalPort 8888 -Protocol TCP -Action Block
    Write-Host "Disabled TCP 21, TCP 22, TCP 23, TCP 25, TCP 80, TCP 8080, TCP 3389, TCP 161 and 162, TCP and UDP on 389 and 636 from inbound rules" -ForegroundColor Yellow -BackgroundColor Black
    New-NetFirewallRule -DisplayName "Block UDP Outbound Port 3389" -Direction Inbound -LocalPort 3389 -Protocol UDP -Action Block
    New-NetFirewallRule -DisplayName "Block UDP Outbound Port 161" -Direction Inbound -LocalPort 161 -Protocol UDP -Action Block
    New-NetFirewallRule -DisplayName "Block UDP Outbound Port 162" -Direction Inbound -LocalPort 162 -Protocol UDP -Action Block
    New-NetFirewallRule -DisplayName "Block UDP Outbound Port 389" -Direction Inbound -LocalPort 389 -Protocol UDP -Action Block
    New-NetFirewallRule -DisplayName "Block UDP Outbound Port 636" -Direction Inbound -LocalPort 636 -Protocol UDP -Action Block
    Write-Host "Disabled UDP 3389, UDP 161, UDP 162, UDP 389, UDP 636" -ForegroundColor Yellow -BackgroundColor Black
    New-NetFirewallRule -DisplayName "sshTCP" -Direction Inbound -LocalPort 22 -Protocol TCP -Action Block #ssh
    New-NetFirewallRule -DisplayName "ftpTCP" -Direction Inbound -LocalPort 21 -Protocol TCP -Action Block #ftp
    New-NetFirewallRule -DisplayName "telnetTCP" -Direction Inbound -LocalPort 23 -Protocol TCP -Action Block #telnet
    New-NetFirewallRule -DisplayName "SMTPTCP" -Direction Inbound -LocalPort 25 -Protocol TCP -Action Block #SMTP
    New-NetFirewallRule -DisplayName "POP3TCP" -Direction Inbound -LocalPort 110 -Protocol TCP -Action Block #POP3
    New-NetFirewallRule -DisplayName "SNMPTCP" -Direction Inbound -LocalPort 161 -Protocol TCP -Action Block #SNMP
    Set-NetConnectionProfile -NetworkCategory Public
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24" -Name "Category" -ErrorAction SilentlyContinue
}



if ($option -eq 2) {
    Write-Host  Configuring Windows Defender... -ForegroundColor Yellow -BackgroundColor Black
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "CheckForSignaturesBeforeRunningScan" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableHeuristics" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "ScanWithAntiVirus" /t REG_DWORD /d 3 /f
    sc.exe config WinDefend start= auto
    sc.exe config WdNisSvc start= demand
    net start WinDefend
    net start WdNisSvc
    Write-Host Updating Windows Defender... -ForegroundColor Yellow -BackgroundColor Black
    & "$env:ProgramFiles\Windows Defender\MpCmdRun.exe" -SignatureUpdate

    Write-Host Configuring miscellaneous settings... -ForegroundColor Yellow -BackgroundColor Black
    #https://www.powershellgallery.com/packages/WindowsDefender_InternalEvaluationSetting
    #Enable real-time monitoring
    Write-Host "Enable real-time monitoring"
    Set-MpPreference -DisableRealtimeMonitoring 0
    #Enable sample submission
    Write-Host "Enable sample submission"
    Set-MpPreference -SubmitSamplesConsent 2
    #Enable checking signatures before scanning
    Write-Host "Enable checking signatures before scanning"
    Set-MpPreference -CheckForSignaturesBeforeRunningScan 1
    #Enable behavior monitoring
    Write-Host "Enable behavior monitoring"
    Set-MpPreference -DisableBehaviorMonitoring 0
    #Enable IOAV protection
    Write-Host "Enable IOAV protection"
    Set-MpPreference -DisableIOAVProtection 0
    #Enable script scanning
    Write-Host "Enable script scanning"
    Set-MpPreference -DisableScriptScanning 0
    #Enable removable drive scanning
    Write-Host "Enable removable drive scanning"
    Set-MpPreference -DisableRemovableDriveScanning 0
    #Enable Block at first sight
    Write-Host "Enable Block at first sight"
    Set-MpPreference -DisableBlockAtFirstSeen 0
    #Enable potentially unwanted 
    Write-Host "Enable potentially unwanted apps"
    Set-MpPreference -PUAProtection Enabled
    #Schedule signature updates every 8 hours
    Write-Host "Schedule signature updates every 8 hours"
    Set-MpPreference -SignatureUpdateInterval 8
    #Enable archive scanning
    Write-Host "Enable archive scanning"
    Set-MpPreference -DisableArchiveScanning 0
    #Enable email scanning
    Write-Host "Enable email scanning"
    Set-MpPreference -DisableEmailScanning 0
    #Enable File Hash Computation
    Write-Host "Enable File Hash Computation"
    Set-MpPreference -EnableFileHashComputation 1
    #Enable Intrusion Prevention System
    Write-Host "Enable Intrusion Prevention System"
    Set-MpPreference -DisableIntrusionPreventionSystem $false
    #Enable Windows Defender Exploit Protection
    Write-Host "Enabling Exploit Protection"
    Set-ProcessMitigation -PolicyFilePath C:\temp\"Windows Defender"\DOD_EP_V3.xml
    #Set cloud block level to 'High'
    Write-Host "Set cloud block level to 'High'"
    Set-MpPreference -CloudBlockLevel High
    #Set cloud block timeout to 1 minute
    Write-Host "Set cloud block timeout to 1 minute"
    Set-MpPreference -CloudExtendedTimeout 50
    Write-Host "`nUpdating Windows Defender Exploit Guard settings`n" -ForegroundColor Green 
    #Enabling Controlled Folder Access and setting to block mode
    #Write-Host "Enabling Controlled Folder Access and setting to block mode"
    #Set-MpPreference -EnableControlledFolderAccess Enabled 
    #Enabling Network Protection and setting to block mode
    Write-Host "Enabling Network Protection and setting to block mode"
    Set-MpPreference -EnableNetworkProtection Enabled

    #Enable Cloud-delivered Protections
    #Set-MpPreference -MAPSReporting Advanced
    #Set-MpPreference -SubmitSamplesConsent SendAllSamples

    #Enable Windows Defender Attack Surface Reduction Rules
    #https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/enable-attack-surface-reduction
    #https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction
    #Block executable content from email client and webmail
    Add-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions Enabled
    #Block all Office applications from creating child processes
    Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled
    #Block Office applications from creating executable content
    Add-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 -AttackSurfaceReductionRules_Actions Enabled
    #Block Office applications from injecting code into other processes
    Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions Enabled
    #Block JavaScript or VBScript from launching downloaded executable content
    Add-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions Enabled
    #Block execution of potentially obfuscated scripts
    Add-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC -AttackSurfaceReductionRules_Actions Enabled
    #Block Win32 API calls from Office macros
    Add-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B -AttackSurfaceReductionRules_Actions Enabled
    #Block executable files from running unless they meet a prevalence, age, or trusted list criterion
    Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-cd74-433a-b99e-2ecdc07bfc25 -AttackSurfaceReductionRules_Actions AuditMode
    #Use advanced protection against ransomware
    Add-MpPreference -AttackSurfaceReductionRules_Ids c1db55ab-c21a-4637-bb3f-a12568109d35 -AttackSurfaceReductionRules_Actions Enabled
    #Block credential stealing from the Windows local security authority subsystem
    Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions Enabled
    #Block process creations originating from PSExec and WMI commands
    Add-MpPreference -AttackSurfaceReductionRules_Ids d1e49aac-8f56-4280-b9ba-993a6d77406c -AttackSurfaceReductionRules_Actions AuditMode
    #Block untrusted and unsigned processes that run from USB
    Add-MpPreference -AttackSurfaceReductionRules_Ids b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 -AttackSurfaceReductionRules_Actions Enabled
    #Block Office communication application from creating child processes
    Add-MpPreference -AttackSurfaceReductionRules_Ids 26190899-1602-49e8-8b27-eb1d0a1ce869 -AttackSurfaceReductionRules_Actions Enabled
    #Block Adobe Reader from creating child processes
    Add-MpPreference -AttackSurfaceReductionRules_Ids 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c -AttackSurfaceReductionRules_Actions Enabled
    #Block persistence through WMI event subscription
    Add-MpPreference -AttackSurfaceReductionRules_Ids e6db77e5-3df2-4cf1-b95a-636979351e5b -AttackSurfaceReductionRules_Actions Enabled
    Set-MpPreference -AllowDatagramProcessingOnWinServer $False
    Set-MpPreference -AllowNetworkProtectionDownLevel $False
    Set-MpPreference -AllowNetworkProtectionOnWinServer $False
    Set-MpPreference -AllowSwitchToAsyncInspection $False
    Set-MpPreference -AttackSurfaceReductionOnlyExclusions ""
    Set-MpPreference -AttackSurfaceReductionRules_Actions ""
    Set-MpPreference -AttackSurfaceReductionRules_Ids ""
    Set-MpPreference -CheckForSignaturesBeforeRunningScan $False
    Set-MpPreference -CloudBlockLevel 0
    Set-MpPreference -CloudExtendedTimeout 0
    Set-MpPreference -ControlledFolderAccessAllowedApplications ""
    Set-MpPreference -ControlledFolderAccessProtectedFolders ""
    Set-MpPreference -DefinitionUpdatesChannel 0
    Set-MpPreference -DisableArchiveScanning $False
    Set-MpPreference -DisableAutoExclusions $False
    Set-MpPreference -DisableBehaviorMonitoring $False
    Set-MpPreference -DisableBlockAtFirstSeen $False
    Set-MpPreference -DisableCatchupFullScan $True
    Set-MpPreference -DisableCatchupQuickScan $True
    Set-MpPreference -DisableCpuThrottleOnIdleScans $True
    Set-MpPreference -DisableDatagramProcessing $False
    Set-MpPreference -DisableDnsOverTcpParsing $False
    Set-MpPreference -DisableDnsParsing $False
    Set-MpPreference -DisableEmailScanning $True
    Set-MpPreference -DisableFtpParsing $False
    Set-MpPreference -DisableGradualRelease $False
    Set-MpPreference -DisableHttpParsing $False
    Set-MpPreference -DisableInboundConnectionFiltering $False
    Set-MpPreference -DisableIOAVProtection $False
    Set-MpPreference -DisableNetworkProtectionPerfTelemetry $False
    Set-MpPreference -DisablePrivacyMode $False
    Set-MpPreference -DisableRdpParsing $False
    Set-MpPreference -DisableRea ltimeMonitoring $False
    Set-MpPreference -DisableRemovableDriveScanning $True
    Set-MpPreference -DisableRestorePoint $True
    Set-MpPreference -DisableScanningMappedNetworkDrivesForFullScan $True
    Set-MpPreference -DisableScanningNetworkFiles $False
    Set-MpPreference -DisableScriptScanning $False
    Set-MpPreference -DisableSshParsing $False
    Set-MpPreference -DisableTDTFeature $False
    Set-MpPreference -DisableTlsParsing $False
    Set-MpPreference -EnableControlledFolderAccess 0
    Set-MpPreference -EnableDnsSinkhole $True
    Set-MpPreference -EnableFileHashComputation $False
    Set-MpPreference -EnableFullScanOnBatteryPower $False
    Set-MpPreference -EnableLowCpuPriority $False
    Set-MpPreference -EnableNetworkProtection 0
    Set-MpPreference -EngineUpdatesChannel 0
    Set-MpPreference -ExclusionExtension ""
    Set-MpPreference -ExclusionIpAddress ""
    Set-MpPreference -ExclusionPath ""
    Set-MpPreference -ExclusionProcess ""
    Set-MpPreference -ForceUseProxyOnly $False
    Set-MpPreference -HighThreatDefaultAction 0
    Set-MpPreference -LowThreatDefaultAction 0
    Set-MpPreference -MAPSReporting 2
    Set-MpPreference -MeteredConnectionUpdates $False
    Set-MpPreference -ModerateThreatDefaultAction 0
    Set-MpPreference -PlatformUpdatesChannel 0
    Set-MpPreference -ProxyBypass ""
    Set-MpPreference -ProxyPacUrl ""
    Set-MpPreference -ProxyServer ""
    Set-MpPreference -PUAProtection 0
    Set-MpPreference -QuarantinePurgeItemsAfterDelay 90
    Set-MpPreference -RandomizeScheduleTaskTimes $True
    Set-MpPreference -RealTimeScanDirection 0
    Set-MpPreference -RemediationScheduleDay 0
    Set-MpPreference -RemediationScheduleTime 020000
    Set-MpPreference -ReportingAdditionalActionTimeOut 10080
    Set-MpPreference -ReportingCriticalFailureTimeOut 10080
    Set-MpPreference -ReportingNonCriticalTimeOut 1440
    Set-MpPreference -ScanAvgCPULoadFactor 50
    Set-MpPreference -ScanOnlyIfIdleEnabled $True
    Set-MpPreference -ScanParameters 1
    Set-MpPreference -ScanPurgeItemsAfterDelay 15
    Set-MpPreference -ScanScheduleDay 0
    Set-MpPreference -ScanScheduleOffset 120
    Set-MpPreference -ScanScheduleQuickScanTime 000000
    Set-MpPreference -ScanScheduleTime 020000
    Set-MpPreference -SchedulerRandomizationTime 4
    Set-MpPreference -ServiceHealthReportInterval 60
    Set-MpPreference -SevereThreatDefaultAction 0
    Set-MpPreference -SharedSignaturesPath ""
    Set-MpPreference -SignatureAuGracePeriod 0
    Set-MpPreference -SignatureBlobFileSharesSources ""
    Set-MpPreference -SignatureBlobUpdateInterval 60
    Set-MpPreference -SignatureDefinitionUpdateFileSharesSources ""
    Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $False
    Set-MpPreference -SignatureFallbackOrder MicrosoftUpdateServer|MMPC
    Set-MpPreference -SignatureFirstAuGracePeriod 120
    Set-MpPreference -SignatureScheduleDay 8
    Set-MpPreference -SignatureScheduleTime 014500
    Set-MpPreference -SignatureUpdateCatchupInterval 1
    Set-MpPreference -SignatureUpdateInterval 0
    Set-MpPreference -SubmitSamplesConsent 1
    Set-MpPreference -ThreatIDDefaultAction_Actions ""
    Set-MpPreference -ThreatIDDefaultAction_Ids ""
    Set-MpPreference -ThrottleForScheduledScanOnly $True
    Set-MpPreference -TrustLabelProtectionStatus 0
    Set-MpPreference -UILockdown False ""
    Set-MpPreference -UnknownThreatDefaultAction 0
    Set-MpPreference -PSComputerName ""
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type Dword -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "ServiceKeepAlive" -Type Dword -Value 1
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableIOAVProtection" -Type Dword -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Type Dword -Value 1
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Type Dword -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Name "CheckForSignaturesBeforeRunningScan" -Type Dword -Value 1
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Name "DisableHeuristics" -Type Dword -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "ScanWithAntiVirus"-Type Dword -Value 3
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\SpyNet" -Name "LocalSettingOverrideSpynetReporting" -Type Dword -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\SpyNet" -Name "SpyNetReporting" -Type Dword -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\SpyNet" -Name "SubmitSamplesConsent" -Type Dword -Value 2
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" -Name "DisableGenericRePorts" -Type Dword -Value 1
    Write-Host Finished configuring Windows Defender. -ForegroundColor Yellow -BackgroundColor Black
    start windowsdefender:
    $wshell = New-Object -ComObject Wscript.Shell
    $wshell.Popup("Run a Windows Defender quick scan",0,"REMINDER",0x1)
}

if ($option -eq 3) {
    $choose = Read-Host 'Enable remote desktop? (y/n)'
    if ($choose -eq "y") {
        Write-Host Enabling remote desktop... -ForegroundColor Yellow -BackgroundColor Black
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v AllowTSConnections /t REG_DWORD /d 1 /f
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fAllowToGetHelp /t REG_DWORD /d 1 /f
        REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 1 /f
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f
        netsh advfirewall firewall set rule group="remote desktop" new enable=yes
        net stop UmRdpService
        net stop TermService
        net start UmRdpService
        net start TermService
        Write-Host Enabled remote desktop. -ForegroundColor Yellow -BackgroundColor Black
        Write-Host Make sure remote desktop is allowed. -ForegroundColor Yellow -BackgroundColor Black
        Write-Host "Please select `"Allow connections only from computers running Remote Desktop with Network Level Authentication (more secure)`"" -ForegroundColor Yellow -BackgroundColor Black
        start SystemPropertiesRemote.exe /wait
    }
    if ($choose -eq "n") {
        Write-Host Disabling remote desktop... -ForegroundColor Yellow -BackgroundColor Black
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDenyTSConnections" -Type Dword -Value 1
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowToGetHelp" -Type Dword -Value 0
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowUnsolicited" -Type Dword -Value 0
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Conferencing" -Name "NoRDS" -Type Dword -Value 1
        Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name "DisablePasswordSaving" -Type Dword -Value 1
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "DisablePasswordSaving" -Type Dword -Value 1
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "CreateEncryptedOnlyTickets" -Type Dword -Value 1
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS" -Name "AllowRemoteShellAccess" -Type Dword -Value 0
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v AllowTSConnections /t REG_DWORD /d 0 /f
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fAllowToGetHelp /t REG_DWORD /d 0 /f
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f
        reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "AllowSignedFiles" /t REG_DWORD /d 0 /f
        reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "AllowUnsignedFiles" /t REG_DWORD /d 0 /f
        reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "DisablePasswordSaving" /t REG_DWORD /d 1 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Conferencing" /v "NoRDS" /t REG_DWORD /d 1 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS" /v "AllowRemoteShellAccess" /t REG_DWORD /d 0 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "AllowSignedFiles" /t REG_DWORD /d 0 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "AllowUnsignedFiles" /t REG_DWORD /d 0 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "CreateEncryptedOnlyTickets" /t REG_DWORD /d 1 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "DisablePasswordSaving" /t REG_DWORD /d 1 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "fAllowToGetHelp" /t REG_DWORD /d 0 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "fAllowUnsolicited" /t REG_DWORD /d 0 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "fDenyTSConnections" /t REG_DWORD /d 1 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client" /v "fEnableUsbBlockDeviceBySetupClass" /t REG_DWORD /d 1 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client" /v "fEnableUsbNoAckIsochWriteToDevice" /t REG_DWORD /d 80 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client" /v "fEnableUsbSelectDeviceByInterface" /t REG_DWORD /d 1 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\RemoteAdminSettings" /v "Enabled" /t REG_DWORD /d 0 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\RemoteDesktop" /v "Enabled" /t REG_DWORD /d 0 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\UPnPFramework" /v "Enabled" /t REG_DWORD /d 0 /f
        New-NetFirewallRule -DisplayName "RDPTCP" -Direction Inbound -LocalPort 3389 -Protocol TCP -Action Block
        netsh advfirewall firewall set rule group="remote desktop" new enable=no
        net stop UmRdpService
        net stop TermService
        Write-Host Disabled remote desktop. -ForegroundColor Yellow -BackgroundColor Black
        Write-Host Make sure remote desktop is not allowed. -ForegroundColor Yellow -BackgroundColor Black
        start SystemPropertiesRemote.exe /wait
    }
}


if ($option -eq 4) {
    Write-Host Configuring miscellaneous registry security keys... -ForegroundColor Yellow -BackgroundColor Black
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa:RunAsPPL" /v RunAsPPL /t REG_DWORD /d 1 /f
    reg add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v  /t REG_MULTI_SZ /d "" /f
    reg ADD "HKCU\Software\Microsoft\Internet Explorer\Main" /v DoNotTrack /t REG_DWORD /d 1 /f
    reg ADD "HKCU\Software\Microsoft\Internet Explorer\Download" /v RunInvalidSignatures /t REG_DWORD /d 1 /f
    reg ADD "HKCU\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN\Settings" /v LOCALMACHINE_CD_UNLOCK /t REG_DWORD /d 1 /t
    reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v DisablePasswordCaching /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AutoInstallMinorUpdates /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AUOptions /t REG_DWORD /d 4 /f
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 4 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v ElevateNonAdmins /t REG_DWORD /d 0 /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoWindowsUpdate /t REG_DWORD /d 0 /f
    reg add "HKLM\SYSTEM\Internet Communication Management\Internet Communication" /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate" /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
    reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateFloppies /t REG_DWORD /d 1 /f
    reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 0 /f
    reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 1 /f
    reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /v AddPrinterDrivers /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v AuditLevel /t REG_DWORD /d 00000008 /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 00000001 /f
    reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f
    reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v auditbaseobjects /t REG_DWORD /d 1 /f
    reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v fullprivilegeauditing /t REG_DWORD /d 1 /f
    reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v restrictanonymous /t REG_DWORD /d 1 /f
    reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v restrictanonymoussam /t REG_DWORD /d 1 /f
    reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v disabledomaincreds /t REG_DWORD /d 1 /f
    reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v everyoneincludesanonymous /t REG_DWORD /d 0 /f
    reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v UseMachineId /t REG_DWORD /d 0 /f
    reg ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v dontdisplaylastusername /t REG_DWORD /d 1 /f
    reg ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 5 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 1 -Force
    reg ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f
    reg ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableInstallerDetection /t REG_DWORD /d 1 /f
    reg ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v undockwithoutlogon /t REG_DWORD /d 0 /f
    reg ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableCAD /t REG_DWORD /d 0 /f
    reg ADD "HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters" /v MaximumPasswordAge /t REG_DWORD /d 15 /f
    reg ADD "HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters" /v DisablePasswordChange /t REG_DWORD /d 1 /f
    reg ADD "HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters" /v RequireStrongKey /t REG_DWORD /d 1 /f
    reg ADD "HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters" /v RequireSignOrSeal /t REG_DWORD /d 1 /f
    reg ADD "HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters" /v SignSecureChannel /t REG_DWORD /d 1 /f
    reg ADD "HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters" /v SealSecureChannel /t REG_DWORD /d 1 /f
    reg ADD "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v autodisconnect /t REG_DWORD /d 45 /f
    reg ADD "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v enablesecuritysignature /t REG_DWORD /d 0 /f
    reg ADD "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v requiresecuritysignature /t REG_DWORD /d 0 /f
    reg ADD "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v NullSessionPipes /t REG_MULTI_SZ /d "" /f
    reg ADD "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v NullSessionShares /t REG_MULTI_SZ /d "" /f
    reg ADD "HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters" /v EnablePlainTextPassword /t REG_DWORD /d 0 /f
    reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths /v Machine" /t REG_MULTI_SZ /d "" /f
    reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths" /v Machine /t REG_MULTI_SZ /d "" /f
    reg ADD "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v EnabledV8 /t REG_DWORD /d 1 /f
    reg ADD "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 1 /f
    reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v DisablePasswordCaching /t REG_DWORD /d 1 /f
    reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnonBadCertRecving /t REG_DWORD /d 1 /f
    reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnOnPostRedirect /t REG_DWORD /d 1 /f
    reg ADD "HKCU\Software\Microsoft\Internet Explorer\Main" /v DoNotTrack /t REG_DWORD /d 1 /f
    reg ADD "HKCU\Software\Microsoft\Internet Explorer\Download" /v RunInvalidSignatures /t REG_DWORD /d 1 /f
    reg ADD "HKCU\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN\Settings" /v LOCALMACHINE_CD_UNLOCK /t REG_DWORD /d 1 /f
    reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnonZoneCrossing /t REG_DWORD /d 1 /f
    reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden /t REG_DWORD /d 1 /f
    reg ADD "HKU\.DEFAULT\Control Panel\Accessibility\StickyKeys" /v Flags /t REG_SZ /d 506 /f
    reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSuperHidden /t REG_DWORD /d 1 /f
    reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v CrashDumpEnabled /t REG_DWORD /d 0 /f
    reg ADD "HKCU\SYSTEM\CurrentControlSet\Services\CDROM" /v AutoRun /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutorun" /t REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\access\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\excel\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\excel\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\excel\security" /v "excelbypassencryptedmacroscan" /t REG_DWORD /d 0 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\ms project\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\ms project\security" /v "level" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\outlook\security" /v "level" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\powerpoint\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\powerpoint\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\publisher\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\visio\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\visio\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\word\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\word\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\word\security" /v "wordbypassencryptedmacroscan" /t REG_DWORD /d 0 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\common\security" /v "automationsecurity" /t REG_DWORD /d 3 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "CheckForSignaturesBeforeRunningScan" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableHeuristics" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "ScanWithAntiVirus" /t REG_DWORD /d 3 /f
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 3 /f
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'HideFileExt' -Value '0'  -Type 'Dword' -Force  # Displays file extensions
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'SharingWizardOn' -Value '0' -Type 'Dword' -Force # Disables Sharing Wizard
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoAutorun' -Value '1' -Type 'Dword' -Force
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun' -Value '255' -Type 'Dword' -Force
    Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers' -Name 'DisableAutoplay' -Value '1' -Type 'Dword' -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FindMyDevice" -Name "AllowFindMyDevice" -Value 0 -Type Dword -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Settings\FindMyDevice" -Name "LocationSyncEnabled" -Value 0 -Type Dword -Force
    Set-ItemProperty -Name "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" -Name "EnhancedAntiSpoofing" -Value 1 -Type Dword -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "BlockDomainPicturePassword" -Value 1 -Type Dword -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Type DWord -Value 0 -Force
    Set-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\" -Name SMBDeviceEnabled -Value 0 -Type Dword -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "Enabled" -Type DWord -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Type DWord -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -Type DWord -Value 1 -Force
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Type Dword -Value 1 -Force
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLinkedConnections" -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareWks" -Type Dword -Value 0 -Force
    Set-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -name DisableExceptionChainValidation -Value 0 -Force
    Set-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -name LocalAccountTokenFilterPolicy -Value 0 -Force
    $TestPath = Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    if($TestPath -match 'False'){
        New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies" -Name Explorer
        }
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -name NoDriveTypeAutoRun -value 0xff -ErrorAction SilentlyContinue -Force
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -name NoDriveTypeAutoRun -value 0xff -Force
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -name DisableAutoplay -value 1 -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -name DisableAutoplay -value 1 -Force
    Set-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Services\CSC" -name Start -value 4 -Force
    Set-ItemProperty -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -name HideFileExt -value 0 -Force

    #Block Untrusted Fonts
    #https://adsecurity.org/?p=3299
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" -Name "MitigationOptions" -Type "QWORD" -Value "1000000000000" -Force

    #Do not let apps on other devices open and message apps on this device, and vice versa
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP" -Name RomeSdkChannelUserAuthzPolicy -PropertyType DWord -Value 1 -Force
    #Turn off Windows Location Provider
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableWindowsLocationProvider" -Type "DWORD" -Value "1" -Force
    #Turn off location scripting
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting" -Type "DWORD" -Value "1" -Force
    #Turn off location
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Value "1" -Type "DWORD" -Force
    #Deny app access to location
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Value "Deny" -Force
    #Deny app access to motion data
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity" -Name "Value" -Value "Deny" -Force

    #Disable LLMNR
    #https://www.blackhillsinfosec.com/how-to-disable-llmnr-why-you-want-to/
    New-Item -Path "HKLM:\Software\policies\Microsoft\Windows NT\" -Name "DNSClient" -Force
    Set-ItemProperty -Path "HKLM:\Software\policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Type "DWORD" -Value 0 -Force

    #Enable LSA Protection/Auditing
    #https://adsecurity.org/?p=3299
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\" -Name "LSASS.exe" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" -Name "AuditLevel" -Type "DWORD" -Value 8 -Force

    Write-Host Configured miscellaneous registry security keys. -ForegroundColor Yellow -BackgroundColor Black
}



if ($option -eq 5) {
    $choose = Read-Host 'Is IIS (FTP included) a critical service? (y/n)'

    if ($choose -eq "y") {
        $servicesB = @("RemoteAccess", "CDPSvc", "XboxGipSvc", "xbgm", "xboxgip", "XblAuthManager", "TabletInputService", "XblGameSave", "HomeGroupListener", "PlugPlay", "Spooler", "UevAgentService", "shpamsvc", "NetTcpPortSharing", "TrkWks", "iphlpsvc", "HomeGroupProvider", "BranchCache", "FDResPub", "Browser", "Telephony", "fdpHost", "TapiSrv", "Tlntsvr", "tlntsvr", "p2pimsvc", "simptcp", "fax", "msftpsvc", "iprip", "ftpsvc", "RemoteRegistry", "RasMan", "RasAuto", "seclogon", "MSFTPSVC", "W3SVC", "TrkWks", "MSDTC", "ERSVC", "NtFrs", "MSFtpsvc", "helpsvc", "HTTPFilter", "IsmServ", "Spooler", "RDSessMgr", "ScardSvr", "Sacsvr", "VDS", "VSS", "WINS", "SZCSVC", "CscServicehidserv", "SharedAccess", "upnphost", "nfssvc") 
        $servicesG = @("Dhcp", "Dnscache", "NtLmSsp", "EventLog", "MpsSvc", "winmgmt", "wuauserv", "CryptSvc", "Schedule", "WdiServiceHost", "WdiSystemHost", "IISADMIN") 
        #servicesB are bad services
        #servicesG are good services
        Write-Host Disabling bad services... -ForegroundColor Yellow -BackgroundColor Black
        ForEach ($serviceB in $servicesB) {
            Write-Host Service: $servicesB -ForegroundColor Yellow -BackgroundColor Black
            sc.exe stop "$serviceB"
            sc.exe config "$serviceB" start= disabled
        }
        Write-Host Disabled bad services. -ForegroundColor Yellow -BackgroundColor Black
        Write-Host Setting services to auto... -ForegroundColor Yellow -BackgroundColor Black
        ForEach ($serviceG in $servicesG) {
            Write-Host Service: $serviceG -ForegroundColor Yellow -BackgroundColor Black
            sc.exe config "$serviceG" start= auto
        }
        Write-Host Started auto services... -ForegroundColor Yellow -BackgroundColor Black
        Get-WindowsOptionalFeature -online | ? featurename -like "IIS" | Enable-WindowsOptionalFeature -Online
        Enable-WindowsOptionalFeature -Online -FeatureName "TFTP"

    } elseif ($choose -eq "n") {
        $servicesB = @("RemoteAccess", "CDPSvc", "XboxGipSvc", "xbgm", "xboxgip", "XblAuthManager", "TabletInputService", "XblGameSave", "HomeGroupListener", "PlugPlay", "Spooler", "UevAgentService", "shpamsvc", "NetTcpPortSharing", "TrkWks", "iphlpsvc", "HomeGroupProvider", "BranchCache", "FDResPub", "Browser", "Telephony", "fdpHost", "TapiSrv", "Tlntsvr", "tlntsvr", "p2pimsvc", "simptcp", "fax", "msftpsvc", "iprip", "ftpsvc", "RemoteRegistry", "RasMan", "RasAuto", "seclogon", "MSFTPSVC", "W3SVC", "TrkWks", "MSDTC", "ERSVC", "NtFrs", "MSFtpsvc", "helpsvc", "HTTPFilter", "IISADMIN", "IsmServ", "Spooler", "RDSessMgr", "ScardSvr", "Sacsvr", "VDS", "VSS", "WINS", "SZCSVC", "CscServicehidserv", "SharedAccess", "upnphost", "nfssvc") 
        $servicesG = @("Dhcp", "Dnscache", "NtLmSsp", "EventLog", "MpsSvc", "winmgmt", "wuauserv", "CryptSvc", "Schedule", "WdiServiceHost", "WdiSystemHost") 
        #servicesB are bad services
        #servicesG are good services
        Write-Host Disabling bad services... -ForegroundColor Yellow -BackgroundColor Black
        ForEach ($serviceB in $servicesB) {
            Write-Host Service: $serviceB -ForegroundColor Yellow -BackgroundColor Black
            sc.exe stop "$serviceB"
            sc.exe config "$serviceB" start= disabled
        }
        Write-Host Disabled bad services. -ForegroundColor Yellow -BackgroundColor Black
        Write-Host Setting services to auto... -ForegroundColor Yellow -BackgroundColor Black
        ForEach ($serviceG in $servicesG) {
            Write-Host Service: $serviceG -ForegroundColor Yellow -BackgroundColor Black
            sc.exe config "$serviceG" start= auto
        }
        Write-Host Started auto services... -ForegroundColor Yellow -BackgroundColor Black
        Get-WindowsOptionalFeature -online | ? featurename -like "IIS" | Disable-WindowsOptionalFeature -Online -Remove

    } else {
        Write-Host Invalid option. -ForegroundColor Yellow -BackgroundColor Black
        select_func
    }
    benji_services
}



if ($option -eq 6) {
    Write-Host Configuring SMB... -ForegroundColor Yellow -BackgroundColor Black

    #SMB Optimizations
    Write-Output "SMB Optimizations"
    Disable-PSRemoting
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "DisableBandwidthThrottling" -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "FileInfoCacheEntriesMax" -Type "DWORD" -Value 1024 -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "DirectoryCacheEntriesMax" -Type "DWORD" -Value 1024 -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "FileNotFoundCacheEntriesMax" -Type "DWORD" -Value 2048 -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "IRPStackSize" -Type "DWORD" -Value 20 -Force
    Set-SmbServerConfiguration -EnableMultiChannel $true -Force 
    Set-SmbServerConfiguration -MaxChannelPerSession 16 -Force
    Set-SmbServerConfiguration -ServerHidden $False -AnnounceServer $False -Force
    Set-SmbServerConfiguration -EnableLeasing $false -Force
    Set-SmbClientConfiguration -EnableLargeMtu $true -Force
    Set-SmbClientConfiguration -EnableMultiChannel $true -Force
    
    #SMB Hardening
    Write-Output "SMB Hardening"
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "RestrictNullSessAccess" -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "RestrictAnonymousSAM" -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "RequireSecuritySignature" -Value 256 -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -Name "RestrictAnonymous" -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Type "DWORD" -Value 1 -Force
    Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart
    Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Client" -NoRestart
    Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Server" -NoRestart
    Set-SmbClientConfiguration -RequireSecuritySignature $True -Force
    Set-SmbClientConfiguration -EnableSecuritySignature $True -Force
    Set-SmbServerConfiguration -EncryptData $true -Force 
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

    Write-Host Finished configuring SMB. -ForegroundColor Yellow -BackgroundColor Black
}



if ($option -eq 7) {
    Write-Host Configuring audit policies... -ForegroundColor Yellow -BackgroundColor Black
    net accounts /uniquepw:24 
    net accounts /maxpwage:30 
    net accounts /minpwage:10 
    net accounts /minpwlen:14 
    net accounts /lockoutduration:30 
    net accounts /lockoutthreshold:10 
    net accounts /lockoutwindow:30
    auditpol /set /subcatergory: "Logon" /success:enable /failure:enable
    auditpol /set /subcatergory: "Logoff" /success:enable /failure:enable
    auditpol /set /subcatergory: "Account Lockout" /success:enable /failure:enable
    auditpol /set /subcatergory: "Other Logon/Logoff Events" /success:enable /failure:enable
    auditpol /set /subcatergory: "Network Policy Server" /success:enable /failure:enable
    auditpol /set /subcatergory: "Registry" /success:enable /failure:enable
    auditpol /set /subcatergory: "SAM" /success:enable /failure:enable
    auditpol /set /subcatergory: "Detailed File Share" /success:enable /failure:enable
    auditpol /set /subcatergory: "Sensitive Privilege" /success:enable /failure:enable
    auditpol /set /subcatergory: "Other Privilege Use Events" /success:enable /failure:enable
    auditpol /set /subcatergory: "DPAPI Activity" /success:enable /failure:enable
    auditpol /set /subcatergory: "RPC Activity" /success:enable /failure:enable
    auditpol /set /subcatergory: "User Account Management" /success:enable /failure:enable
    auditpol /set /subcatergory: "Security Group Management" /success:enable /failure:enable
    auditpol /set /subcatergory: "Distribution Group" /success:enable /failure:enable
    auditpol /set /category: "Account Logon" /success:enable
    auditpol /set /category: "Account Logon" /failure:enable
    auditpol /set /category: "Account Management" /success:enable
    auditpol /set /category: "Account Management" /failure:enable
    auditpol /set /category: "DS Access" /success:enable
    auditpol /set /category: "DS Access" /failure:enable
    auditpol /set /category: "Logon/Logoff" /success:enable
    auditpol /set /category: "Logon/Logoff" /failure:enable
    auditpol /set /category: "Object Access" /success:enable
    auditpol /set /category: "Object Access" /failure:enable
    auditpol /set /category: "Policy Change" /success:enable
    auditpol /set /category: "Policy Change" /failure:enable
    auditpol /set /category: "Privilege Use" /success:enable
    auditpol /set /category: "Privilege Use" /failure:enable
    auditpol /set /category: "Detailed Tracking" /success:enable
    auditpol /set /category: "Detailed Tracking" /failure:enable
    auditpol /set /category: "System" /success:enable 
    auditpol /set /category: "System" /failure:enable
    Write-Host Completed configuring audit policies. -ForegroundColor Yellow -BackgroundColor Black
}


if ($option -eq 8) {
    Write-Host Setting proper account properties... -ForegroundColor Yellow -BackgroundColor Black
    powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_NONE CONSOLELOCK 1
    powercfg /SETDCVALUEINDEX SCHEME_CURRENT SUB_NONE CONSOLELOCK 1
    powercfg -SETDCVALUEINDEX SCHEME_BALANCED SUB_NONE CONSOLELOCK 1
    powercfg -SETACVALUEINDEX SCHEME_BALANCED SUB_NONE CONSOLELOCK 1
    powercfg -SETDCVALUEINDEX SCHEME_MIN SUB_NONE CONSOLELOCK 1
    powercfg -SETDCVALUEINDEX SCHEME_MIN SUB_NONE CONSOLELOCK 1
    powercfg -SETDCVALUEINDEX SCHEME_MAX SUB_NONE CONSOLELOCK 1
    powercfg -SETDCVALUEINDEX SCHEME_MAX SUB_NONE CONSOLELOCK 1
    wmic userAccount set PasswordChangeable=true
    wmic useraccount set PasswordExpires=true
    wmic useraccount set PasswordRequired=true
    wmic UserAccount set Lockout=False
    Get-LocalUser Guest | Disable-LocalUser
    Get-LocalUser Administrator | Disable-LocalUser
    wmic useraccount where name=`'Administrator`' set disabled=true
    wmic useraccount where name=`'Guest`' set disabled=true
    wmic userAccount where name=`"Guest`" set PasswordChangeable=false
    wmic useraccount where name=`"$env:Username`" set PasswordExpires=false
    wmic useraccount where name=`"$env:Username`" set PasswordRequired=false
    
    # Get all user accounts on the PC
    $users = Get-LocalUser
    # Loop through each user account
    foreach ($user in $users) {
        # Generate a new password
        $newPassword = ConvertTo-SecureString -String "ComCorpTeam8786!!!" -AsPlainText -Force

        # Set the new password for the user
        Set-LocalUser -Name $user.Name -Password $newPassword
    }

    $Exclude = "Administrator","Guest","DefaultAccount","WDAGUtilityAccount","$env:USERNAME"
    Get-LocalUser | Where {$Exclude -notcontains $_.Name} | 
    Set-Localuser -Password (ConvertTo-SecureString -AsPlainText "ComCorpTeam8786!!!" -Force) -PasswordNeverExpires $false -UserMayChangePassword $true

    Write-Host Set proper account properties. -ForegroundColor Yellow -BackgroundColor Black
}



if ($option -eq 9) {
    start sdclt.exe /configure
    Write-Host Started Windows Backup. -ForegroundColor Yellow -BackgroundColor Black
}



if ($option -eq 10) {
    iex "& { $(irm https://aka.ms/install-powershell.ps1) } -UseMSI"
    Write-Host Completed updating powershell. -ForegroundColor Yellow -BackgroundColor Black
}



if ($option -eq 11) {
    Write-Host PowerShell downloading SysInternals... -ForegroundColor Yellow -BackgroundColor Black
    Write-Host This might take a while... -ForegroundColor Yellow -BackgroundColor Black
    Invoke-WebRequest -OutFile SysinternalsSuite.zip https://download.sysinternals.com/files/SysinternalsSuite.zip
    md ~\Downloads\SysInternals
    Expand-Archive SysinternalsSuite.zip -DestinationPath ~\Downloads\SysInternals
    Write-Host Completed downloading and extracting SysInternals. It is located in your downloads folder. -ForegroundColor Yellow -BackgroundColor Black
}



if ($option -eq 12) {
    Write-Host PowerShell downloading AVG Antivirus... -ForegroundColor Yellow -BackgroundColor Black
    $dir = '~\Downloads'
    Set-Location $dir
    Invoke-WebRequest -OutFile avg_antivirus_free_setup.exe https://bits.avcdn.net/productfamily_ANTIVIRUS/insttype_FREE/platform_WIN_AVG/installertype_ONLINE/build_RELEASE/cookie_mmm_bav_tst_005_482_d
    Write-Host Completed downloading AVG Antivirus. It is located in your downloads folder. -ForegroundColor Yellow -BackgroundColor Black
    start avg_antivirus_free_setup.exe /wait
}



if ($option -eq 13) {
    Write-Host PowerShell downloading Malwarebytes...
    $dir = '~\Downloads'
    Set-Location $dir
    Invoke-WebRequest -OutFile MBSetup.exe https://data-cdn.mbamupdates.com/web/mb4-setup-consumer/MBSetup.exe
    Write-Host Completed downloading Malwarebytes. It is located in your downloads folder.
    start MBSetup.exe /wait
}



if ($option -eq 14) {
    Write-Host Flushing DNS cache... -ForegroundColor Yellow -BackgroundColor Black
    ipconfig /flushdns
    netsh interface ipv4 delete arpcache
    netsh interface ipv4 delete destinationcache
    netsh interface ipv4 delete neighbors
    Set-Variable -Name 'Adapter' -Value (Get-NetAdapter -Name 'Ethernet*' -Physical | Select-Object -ExpandProperty 'Name')
    netsh interface ipv4 delete winsservers $Adapter all
    Remove-Item -Path "$env:SystemRoot\System32\drivers\etc\hosts" -force
    New-Item -Path "$env:SystemRoot\System32\drivers\etc" -Name 'hosts' -ItemType 'file' -Value '# Flushed.' -Force
    attrib -r -s C:\WINDOWS\system32\drivers\etc\hosts
    Write-Host > C:\Windows\System32\drivers\etc\hosts -ForegroundColor Yellow -BackgroundColor Black
    Write-Host 127.0.0.1 localhost >> C:\Windows\System32\drivers\etc\hosts -ForegroundColor Yellow -BackgroundColor Black
    Write-Host localhost 127.0.0.1 >> C:\Windows\System32\drivers\etc\hosts -ForegroundColor Yellow -BackgroundColor Black
    Write-Host Flushed DNS Cache. -ForegroundColor Yellow -BackgroundColor Black
}



if ($option -eq 15) {
    Write-Host Configuring Windows Features... -ForegroundColor Yellow -BackgroundColor Black
    dism /online /disable-feature /featurename:IIS-WebServerRole
    dism /online /disable-feature /featurename:IIS-WebServer
    dism /online /disable-feature /featurename:IIS-CommonHttpFeatures
    dism /online /disable-feature /featurename:IIS-HttpErrors
    dism /online /disable-feature /featurename:IIS-HttpRedirect
    dism /online /disable-feature /featurename:IIS-ApplicationDevelopment
    dism /online /disable-feature /featurename:IIS-NetFxExtensibility
    dism /online /disable-feature /featurename:IIS-NetFxExtensibility45
    dism /online /disable-feature /featurename:IIS-HealthAndDiagnostics
    dism /online /disable-feature /featurename:IIS-HttpLogging
    dism /online /disable-feature /featurename:IIS-LoggingLibraries
    dism /online /disable-feature /featurename:IIS-RequestMonitor
    dism /online /disable-feature /featurename:IIS-HttpTracing
    dism /online /disable-feature /featurename:IIS-Security
    dism /online /disable-feature /featurename:IIS-URLAuthorization
    dism /online /disable-feature /featurename:IIS-RequestFiltering
    dism /online /disable-feature /featurename:IIS-IPSecurity
    dism /online /disable-feature /featurename:IIS-Performance
    dism /online /disable-feature /featurename:IIS-HttpCompressionDynamic
    dism /online /disable-feature /featurename:IIS-WebServerManagementTools
    dism /online /disable-feature /featurename:IIS-ManagementScriptingTools
    dism /online /disable-feature /featurename:IIS-IIS6ManagementCompatibility
    dism /online /disable-feature /featurename:IIS-Metabase
    dism /online /disable-feature /featurename:IIS-HostableWebCore
    dism /online /disable-feature /featurename:IIS-StaticContent
    dism /online /disable-feature /featurename:IIS-DefaultDocument
    dism /online /disable-feature /featurename:IIS-DirectoryBrowsing
    dism /online /disable-feature /featurename:IIS-WebDAV
    dism /online /disable-feature /featurename:IIS-WebSockets
    dism /online /disable-feature /featurename:IIS-ApplicationInit
    dism /online /disable-feature /featurename:IIS-ASPNET
    dism /online /disable-feature /featurename:IIS-ASPNET45
    dism /online /disable-feature /featurename:IIS-ASP
    dism /online /disable-feature /featurename:IIS-CGI
    dism /online /disable-feature /featurename:IIS-ISAPIExtensions
    dism /online /disable-feature /featurename:IIS-ISAPIFilter
    dism /online /disable-feature /featurename:IIS-ServerSideIncludes
    dism /online /disable-feature /featurename:IIS-CustomLogging
    dism /online /disable-feature /featurename:IIS-BasicAuthentication
    dism /online /disable-feature /featurename:IIS-HttpCompressionStatic
    dism /online /disable-feature /featurename:IIS-ManagementConsole
    dism /online /disable-feature /featurename:IIS-ManagementService
    dism /online /disable-feature /featurename:IIS-WMICompatibility
    dism /online /disable-feature /featurename:IIS-LegacyScripts
    dism /online /disable-feature /featurename:IIS-LegacySnapIn
    dism /online /disable-feature /featurename:IIS-FTPServer
    dism /online /disable-feature /featurename:IIS-FTPSvc
    dism /online /disable-feature /featurename:IIS-FTPExtensibility
    dism /online /disable-feature /featurename:TFTP
    dism /online /disable-feature /featurename:TelnetClient
    dism /online /disable-feature /featurename:TelnetServer
    dism /online /disable-feature /featurename:SMB1Protocol
    Write-Host Completed configuring Windows Features. -ForegroundColor Yellow -BackgroundColor Black
}



if ($option -eq 16) {
    Write-Host Configuring Internet Explorer settings... -ForegroundColor Yellow -BackgroundColor Black
    # Disable Geolocation in Internet Explorer.
    Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Internet Explorer\Geolocation" -Name "PolicyDisableGeolocation" -Type Dword -Value 1

    # Enable Internet Explorer phishing filter.
    Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter" -Name "EnabledV9" -Type Dword -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\PhishingFilter" -Name "EnabledV9" -Type Dword -Value 1

    # Disable Internet Explorer phishing filter.
    # Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter" -Name "EnabledV9" -Type Dword -Value 0
    # Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\PhishingFilter" -Name "EnabledV9" -Type Dword -Value 0

    # Disable Internet Explorer InPrivate logging.
    Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Internet Explorer\Safety\PrivacIE" -Name "DisableLogging" -Type Dword -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Safety\PrivacIE" -Name "DisableLogging" -Type Dword -Value 1

    # Disable Internet Explorer CEIP.
    Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Internet Explorer\SQM" -Name "DisableCustomerImprovementProgram" -Type Dword -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\SQM" -Name "DisableCustomerImprovementProgram" -Type Dword -Value 0

    # Disable enhanced, and other suggestions.
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer" -Name "AllowServicePoweredQSA" -Type Dword -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\DomainSuggestion" -Name "Enabled" -Type Dword -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\SearchScopes" -Name "TopResult" -Type Dword -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Suggested Sites" -Name "Enabled" -Type Dword -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Name "AutoSearch" -Type Dword -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\WindowsSearch" -Name "EnabledScopes" -Type Dword -Value 0

    # Disable continuous browsing.
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\ContinuousBrowsing" -Name "Enabled" -Type Dword -Value 0

    # Enable DEP and isolation in Internet Explorer.
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Name "DEPOff" -Type Dword -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Name "Isolation64Bit" -Type Dword -Value 1

    # Disable prefetching in Internet Explorer.
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\PrefetchPrerender" -Name "Enabled" -Type Dword -Value 0

    # Disable crash detection in Internet Explorer.
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Restrictions" -Name "NoCrashDetection" -Type Dword -Value 1

    # Send the Do Not Track (DNT) request header in Internet Explorer.
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Name "DoNotTrack" -Type Dword -Value 1

    # Clear browsing history on exit in Internet Explorer.
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Privacy" -Name "ClearBrowsingHistoryOnExit" -Type Dword -Value 1

    # Disable SSLv3 fallback, and the ability to ignore certificate errors, in Internet Explorer.
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "CallLegacyWCMPolicies" -Type Dword -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "EnableSSL3Fallback" -Type Dword -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "PreventIgnoreCertErrors" -Type Dword -Value 1

    # Force enabled HTTP/2 in Internet Explorer.
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "EnableHTTP2" -Type Dword -Value 1
    Write-Host Configured Internet Explorer settings. -ForegroundColor Yellow -BackgroundColor Black
}



if ($option -eq 17) {
    Write-Host Disabling NetBIOS... -ForegroundColor Yellow -BackgroundColor Black

    $key = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"

    Get-ChildItem $key |
    foreach { 
    Write-Host("Modify $key\$($_.pschildname)")
    $NetbiosOptions_Value = (Get-ItemProperty "$key\$($_.pschildname)").NetbiosOptions
    Write-Host("NetbiosOptions updated value is $NetbiosOptions_Value")
    }

    Write-Host Disabled NetBIOS. -ForegroundColor Yellow -BackgroundColor Black
}



if ($option -eq 18) {
    Write-Host Searching for media files in C:\Users and moving them to C:\ComCorp\mediafiles... -ForegroundColor Yellow -BackgroundColor Black

    New-Item -Path "C:\ComCorp\mediafiles" -ItemType directory
    Get-ChildItem -Path "C:\Users\*" -Include *.mp3,*.aif,*.iff,*.m3u,*.m4a,*.mid,*.wav,*.wma,*.avi,*.m4v,*.mov,*.mpg,*.swf,*.wmv, *.jpg, *.jpeg, *.png, *gif, *password*  -Recurse | Move-Item -Destination "C:\ComCorp\mediafiles" 

    Write-Host Moved media files in C:\Users to C:\ComCorp\mediafiles. -ForegroundColor Yellow -BackgroundColor Black
}


if ($option -eq 19) {
    Write-Host Configuring Google Chrome settings... -ForegroundColor Yellow -BackgroundColor Black

    # First, check if Google Chrome is installed
    $chromePath = "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe"
    if (!(Test-Path $chromePath)) {
      Write-Output "Google Chrome is not installed on this machine."
      return
    }

    # Check for updates to Google Chrome
    $updates = Get-WmiObject -Class Win32SoftwareUpdate -Filter "TargetSoftware='{8A69D345-D564-463C-AFF1-A69D9E530F96}'"
    if ($updates.Count -eq 0) {
      Write-Output "No updates are available for Google Chrome."
      return
    }

    # Install the updates
    $updates | ForEach-Object -InputObject {$_.Install()}

    reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AdvancedProtectionAllowed" /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AllowCrossOriginAuthPrompt" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AlwaysOpenPdfExternally" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AmbientAuthenticationInPrivateModesEnabled" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AudioCaptureAllowed" /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AudioSandboxEnabled" /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "BlockExternalExtensions" /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "SSLVersionMin" /t REG_SZ /d tls1 /f
    reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "ScreenCaptureAllowed" /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "SitePerProcess" /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "TLS13HardeningForLocalAnchorsEnabled" /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "VideoCaptureAllowed" /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AllowFileSelectionDialogs" /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AlwaysOpenPdfExternally" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AutoFillEnabled" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "BlockThirdPartyCookies" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "PasswordManagerEnabled" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "MetricsReportingEnabled" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "ImportSavedPasswords" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "CloudPrintSubmitEnabled" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "CloudPrintProxyEnabled" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AllowOutdatedPlugins" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AlternateErrorPagesEnabled" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DnsOverHttpsMode" /t REG_SZ /d "secure" /f

    # Set the Google Chrome policies
    $policies = @{
      "ExtensionInstallBlacklist" = "*"
      "ExtensionInstallWhitelist" = "*"
      "ExtensionInstallForcelist" = "*"
      "ExtensionAllowedTypes" = "*"
      "ExtensionSettings" = "*"
      "ExtensionInstallSources" = "*"
      "HomepageLocation" = "*"
      "BlockExternalExtensions" = "True"
      "AllowOutdatedPlugins" = "False"
      "BlockPrompts" = "*"
      "BookmarkBarEnabled" = "*"
      "BlockWebGL" = "*"
      "ClearSiteDataOnExit" = "True"
      "CookiesBlockedForUrls" = "*"
      "DefaultCookiesSetting" = "Block"
      "DefaultSearchProviderEnabled" = "*"
      "DefaultSearchProviderName" = "*"
      "DefaultSearchProviderSearchURL" = "*"
      "DefaultSearchProviderSuggestURL" = "*"
      "DevToolsDisabled" = "*"
      "DnsPrefetchingEnabled" = "False"
      "DomStorageEnabled" = "False"
      "FullscreenAllowed" = "*"
      "GeolocationDisabled" = "True"
      "IncognitoModeAvailability" = "Enabled"
      "NativeFileSystemWriteAccessBlocked" = "True"
      "PasswordManagerEnabled" = "False"
      "PopupsBlockedForUrls" = "*"
      "ProtectSyncCredential" = "True"
      "QuicAllowed" = "False"
      "ReferrersEnabled" = "False"
      "SafeBrowsingEnabled" = "True"
      "SafeBrowsingExtendedReportingEnabled" = "True"
      "SafeBrowsingWarningsEnabled" = "True"
      "ScreenCaptureAllowed" = "*"
      "WebRtcLocalIpAddress" = "*"
      "WebRtcLocalIpsAllowedUrls" = "*"
      "WebRtcMultipleRoutesEnabled" = "*"
      "WebRtcUdpPortRange" = "*"
      "WebUsbAskForUrls" = "*"
      "WebUsbBlockedForUrls" = "*"
      "WebUsbSecurity" = "*"
    }

    # Set the policies in Google Chrome
    foreach ($key in $policies.Keys) {
      $policy = New-Item -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name $key -Force
      Set-ItemProperty -Path $policy.PsPath -Name "Default" -Type String -Value $policies[$key]
    }

    # Restart Google Chrome for the policies to take effect
    Start-Process "$chromePath"

    Write-Host Completed configuring Google Chrome Settings. -ForegroundColor Yellow -BackgroundColor Black
}

if ($option -eq 20) {
    Write-Host Starting system integrity scan... -ForegroundColor Yellow -BackgroundColor Black
    Sfc.exe /scannow
}

if ($option -eq 21) {
    # Load the Firefox.Application COM object
    $firefoxApp = New-Object -ComObject Firefox.Application

    # Get the preferences object
    $prefs = $firefoxApp.preferences

    # Disable automatic updates
    $prefs.setIntPref("app.update.auto", 1)
    $prefs.setIntPref("app.update.enabled", 1)

    # Set security-related preferences
    $prefs.setBoolPref("security.insecure_password.ui.enabled", $true)
    $prefs.setBoolPref("security.insecure_field_warning.contextual.enabled", $true)
    $prefs.setIntPref("security.tls.version.min", 3)
    $prefs.setIntPref("security.tls.version.max", 4)
    $prefs.setBoolPref("security.ssl.treat_unsafe_negotiation_as_broken", $true)
    $prefs.setIntPref("security.cert_pinning.enforcement_level", 2)
    $prefs.setBoolPref("security.cert_pinning.require_cert_date_before_or_at_build_date", $true)

    # Set privacy-related preferences
    $prefs.setBoolPref("privacy.trackingprotection.enabled", $true)
    $prefs.setBoolPref("privacy.trackingprotection.socialtracking.enabled", $true)
    $prefs.setBoolPref("privacy.resistFingerprinting", $true)
    $prefs.setBoolPref("privacy.firstparty.isolate", $true)

    # Set other preferences
    $prefs.setBoolPref("browser.formfill.enable", $false)
    $prefs.setIntPref("network.cookie.cookieBehavior", 2)
    $prefs.setBoolPref("browser.safebrowsing.phishing.enabled", $true)
    $prefs.setBoolPref("browser.safebrowsing.malware.enabled", $true)

    # Save preferences
    $prefs.save()


}


if ($option -eq 22) {

    # Get a list of installed software
    $installedSoftware = Get-WmiObject -Class Win32Product

    # Iterate over each piece of installed software
    foreach ($software in $installedSoftware) {
      # Check if the software has an update available
      $updates = Get-WmiObject -Class Win32SoftwareUpdate -Filter "TargetSoftware='$($software.IdentifyingNumber)'"
      if ($updates.Count -gt 0) {
        # Install the updates
        $updates | ForEach-Object -InputObject {$_.Install()}
  }
}


}

function benji_services(){
    Write-Host Configuring all services... -ForegroundColor Yellow -BackgroundColor Black
    sc.exe config AxInstSV start= disabled
    sc.exe config AJRouter start= disabled
    sc.exe config AppReadiness start= demand
    sc.exe config AppHostSvc start= auto
    sc.exe config AppIDSvc start= demand
    sc.exe config Appinfo start= demand
    sc.exe config ALG start= disabled
    sc.exe config AppMgmt start= demand
    sc.exe config AppXSVC start= demand
    sc.exe config aspnet_state start= demand
    sc.exe config AssignedAccessManagerSvc start= demand
    sc.exe config tzautoupdate start= disabled
    sc.exe config BthAvctpSvc start= disabled
    sc.exe config BITS start= auto
    sc.exe config BrokerInfrastructure start= auto
    sc.exe config BFE start= auto
    sc.exe config BDESVC start= demand
    sc.exe config wbengine start= demand
    sc.exe config BTAGService start= disabled
    sc.exe config BthHFSrv start= disabled
    sc.exe config bthserv start= disabled
    sc.exe config BluetoothUserService_????? start= demand
    sc.exe config PeerDistSvc start= disabledCDPSvc
    sc.exe config camsvc start= demand
    sc.exe config CaptureService_????? start= disabled
    sc.exe config CDPSvc start= auto
    sc.exe config CertPropSvc start= disabled
    sc.exe config c2wts start= demand
    sc.exe config c2wts start= demand
    sc.exe config NfsClnt start= disabled
    sc.exe config ClipSVC start= demand
    sc.exe config KeyIso start= demand
    sc.exe config EventSystem start= auto
    sc.exe config COMSysApp start= demand
    sc.exe config Browser start= demand
    sc.exe config CDPSvc start= auto
    sc.exe config CDPUserSvc_????? start= auto
    sc.exe config DiagTrack start= auto
    sc.exe config PimIndexMaintenanceSvc_????? start= demand
    sc.exe config CoreMessagingRegistrar start= auto
    sc.exe config CoreUIRegistrar start= auto
    sc.exe config VaultSvc start= demand
    sc.exe config CryptSvc start= auto
    sc.exe config DsSvc start= demand
    sc.exe config DusmSvc start= auto
    sc.exe config DcpSvc start= disabled
    sc.exe config DcomLaunch start= auto
    sc.exe config DoSvc start= auto
    sc.exe config DeviceAssociationService start= demand
    sc.exe config DeviceInstall start= demand
    sc.exe config DmEnrollmentSvc start= demand
    sc.exe config DsmSVC start= demand
    sc.exe config DevicePickerUserSvc_????? start= demand
    sc.exe config DevicesFlowUserSvc_????? start= demand
    sc.exe config DevQueryBroker start= demand
    sc.exe config Dhcp start= auto
    sc.exe config diagsvc start= demand
    sc.exe config DPS start= auto
    sc.exe config WdiServiceHost start= demand
    sc.exe config WdiSystemHost start= demand
    sc.exe config DiagTrack start= disabled
    sc.exe config TrkWks start= auto
    sc.exe config MSDTC start= demand
    sc.exe config dmwappushsvc start= disabled
    sc.exe config Dnscache start= auto
    sc.exe config MapsBroker start= disabled
    sc.exe config DsRoleSvc start= demand
    sc.exe config embeddedmode start= demand
    sc.exe config embeddedmode start= demand
    sc.exe config EFS start= demand
    sc.exe config EntAppSvc start= demand
    sc.exe config EapHost start= demand
    sc.exe config Fax start= disabled
    sc.exe config fhsvc start= demand
    sc.exe config fdPHost start= demand
    sc.exe config FDResPub start= demand
    sc.exe config BcastDVRUserService_????? start= demand
    sc.exe config lfsvc start= disabled
    sc.exe config GraphicsPerfSvc start= demand
    sc.exe config gpsvc start= auto
    sc.exe config hkmsvc start= disabled
    sc.exe config HomeGroupListener start= demand
    sc.exe config HomeGroupProvider start= demand
    sc.exe config hns start= demand
    sc.exe config hidserv start= demand
    sc.exe config HvHost start= disabled
    sc.exe config vmickvpexchange start= disabled
    sc.exe config vmicguestinterface start= disabled
    sc.exe config vmicshutdown start= disabled
    sc.exe config vmicheartbeat start= disabled
    sc.exe config vmcompute start= demand
    sc.exe config vmicvmsession start= disabled
    sc.exe config vmicrdv start= disabled
    sc.exe config vmictimesync start= disabled
    sc.exe config vmms start= disabled
    sc.exe config vmicvmsession start= disabled
    sc.exe config vmicvss start= disabled
    sc.exe config IKEEXT start= demand
    sc.exe config irmon start= disabled
    sc.exe config cphs start= demand
    sc.exe config ? start= auto
    sc.exe config UI0Detect start= demand
    sc.exe config SharedAccess start= disabled
    sc.exe config IEEtwCollectorService start= disabled
    sc.exe config iphlpsvc start= disabled
    sc.exe config IpxlatCfgSvc start= disabled
    sc.exe config PolicyAgent start= demand
    sc.exe config KtmRm start= demand
    sc.exe config lltdsvc start= demand
    sc.exe config LSM start= auto
    sc.exe config wlpasvc start= demand
    sc.exe config LPDSVC start= disabled
    sc.exe config LxssManager start= disabled
    sc.exe config MSMQ start= disabled
    sc.exe config MSMQTriggers start= disabled
    sc.exe config MessagingService_????? start= demand
    sc.exe config diagnosticshub.standardcollector.service start= demand
    sc.exe config wlidsvc start= disabled
    sc.exe config AppVClient start= disabled
    sc.exe config ftpsvc start= disabled
    sc.exe config MSiSCSI start= disabled
    sc.exe config MsKeyboardFilter start= disabled
    sc.exe config NgcSvc start= demand
    sc.exe config NgcCtnrSvc start= demand
    sc.exe config swprv start= demand
    sc.exe config smphost start= demand
    sc.exe config InstallService start= demand
    sc.exe config SmsRouter start= disabled
    sc.exe config WmsRepair start= disabled
    sc.exe config Wms start= disabled
    sc.exe config NaturalAuthentication start= disabled
    sc.exe config NetMsmqActivator start= disabled
    sc.exe config NetPipeActivator start= disabled
    sc.exe config NetTcpActivator start= disabled
    sc.exe config NetTcpPortSharing start= disabled
    sc.exe config Netlogon start= disabled
    sc.exe config Netlogon start= disabled
    sc.exe config NcdAutoSetup start= disabled
    sc.exe config NcbService start= demand
    sc.exe config Netman start= demand
    sc.exe config NcaSVC start= demand
    sc.exe config netprofm start= demand
    sc.exe config NlaSvc start= auto
    sc.exe config NetSetupSvc start= demand
    sc.exe config nsi start= auto
    sc.exe config CscService start= disabled
    sc.exe config ssh-agent start= demand
    sc.exe config defragsvc start= demand
    sc.exe config WpcMonSvc start= disabled
    sc.exe config SEMgrSvc start= disabled
    sc.exe config PNRPsvc start= demand
    sc.exe config p2psvc start= demand
    sc.exe config p2pimsvc start= demand
    sc.exe config PerfHost start= demand
    sc.exe config pla start= demand
    sc.exe config PhoneSvc start= disabled
    sc.exe config PlugPlay start= demand
    sc.exe config PNRPAutoReg start= demand
    sc.exe config WPDBusEnum start= demand
    sc.exe config Power start= auto
    sc.exe config Spooler start= auto
    sc.exe config PrintNotify start= demand
    sc.exe config PrintWorkflowUserSvc_????? start= demand
    sc.exe config wercplsupport start= demand
    sc.exe config PcaSvc start= auto
    sc.exe config QWAVE start= demand
    sc.exe config RmSvc start= demand
    sc.exe config RasAuto start= disabled
    sc.exe config RasMan start= disabled
    sc.exe config SessionEnv start= disabled
    sc.exe config TermService start= disabled
    sc.exe config RpcSs start= auto
    sc.exe config RpcLocator start= disabled
    sc.exe config RemoteRegistry start= disabled
    sc.exe config RetailDemo start= disabled
    sc.exe config iprip start= disabled
    sc.exe config RemoteAccess start= disabled
    sc.exe config RpcEptMapper start= auto
    sc.exe config seclogon start= demand
    sc.exe config SstpSvc start= demand
    sc.exe config SamSs start= auto
    sc.exe config wscsvc start= auto
    sc.exe config SensorDataService start= disabled
    sc.exe config SensrSvc start= disabled
    sc.exe config SensorService start= disabled
    sc.exe config LanmanServer start= disabled
    sc.exe config shpamsvc start= disabled
    sc.exe config ShellHWDetection start= auto
    sc.exe config simptcp start= disabled
    sc.exe config SCardSvr start= disabled
    sc.exe config ScDeviceEnum start= disabled
    sc.exe config SCPolicySvc start= disabled
    sc.exe config SNMP start= disabled
    sc.exe config SNMPTRAP start= disabled
    sc.exe config sppsvc start= auto
    sc.exe config SharedRealitySvc start= demand
    sc.exe config svsvc start= demand
    sc.exe config SSDPSRV start= demand
    sc.exe config StateRepository start= demand
    sc.exe config WiaRpc start= demand
    sc.exe config StorSvc start= disabled
    sc.exe config TieringEngineService start= demand
    sc.exe config SysMain start= auto
    sc.exe config OneSyncSvc_????? start= auto
    sc.exe config SENS start= auto
    sc.exe config SENS start= auto
    sc.exe config SystemEventsBroker start= auto
    sc.exe config SgrmBroker start= auto
    sc.exe config Schedule start= auto
    sc.exe config lmhosts start= demand
    sc.exe config TapiSrv start= disabled
    sc.exe config Themes start= auto
    sc.exe config tiledatamodelsvc start= auto
    sc.exe config TimeBroker start= auto
    sc.exe config TokenBroker start= demand
    sc.exe config TabletInputService start= demand
    sc.exe config UwfServcingSvc start= disabled
    sc.exe config UsoSvc start= disabled
    sc.exe config UsoSvc start= demand
    sc.exe config upnphost start= demand
    sc.exe config UserDataSvc_????? start= disabled
    sc.exe config UnistoreSvc_????? start= demand
    sc.exe config UevAgentService start= demand
    sc.exe config UserManager start= disabled
    sc.exe config ProfSvc start= auto
    sc.exe config vds start= auto
    sc.exe config VSS start= demand
    sc.exe config W3LOGSVC start= demand
    sc.exe config WalletService start= demand
    sc.exe config WarpJITSvc start= disabled
    sc.exe config WMSVC start= demand
    sc.exe config WebClient start= disabled
    sc.exe config WFDSConSvc start= disabled
    sc.exe config AudioSrv start= disabled
    sc.exe config AudioEndpointBuilder start= auto
    sc.exe config SDRSVC start= auto
    sc.exe config WbioSrvc start= demand
    sc.exe config FrameServer start= disabled
    sc.exe config wcncsvc start= disabled
    sc.exe config Wcmsvc start= disabled
    sc.exe config Sense start= auto
    sc.exe config WdNisSvc start= demand
    sc.exe config WinDefend start= auto
    sc.exe config WdNisSvc start= auto
    sc.exe config SecurityHealthService start= demand
    sc.exe config WinDefend start= auto
    sc.exe config wudfsvc start= auto
    sc.exe config WEPHOSTSVC start= auto
    sc.exe config WerSvc start= demand
    sc.exe config Wecsvc start= demand
    sc.exe config EventLog start= demand
    sc.exe config MpsSvc start= auto
    sc.exe config FontCache start= auto
    sc.exe config StiSvc start= auto
    sc.exe config wisvc start= demand
    sc.exe config msiserver start= disabled
    sc.exe config LicenseManager start= demand
    sc.exe config Winmgmt start= demand
    sc.exe config WMPNetworkSvc start= auto
    sc.exe config icssvc start= disabled
    sc.exe config TrustedInstaller start= disabled
    sc.exe config Wms start= demand
    sc.exe config WmsRepair start= disabled
    sc.exe config spectrum start= disabled
    sc.exe config FontCache3.0.0.0 start= demand
    sc.exe config WAS start= disabled
    sc.exe config WpnService start= disabled
    sc.exe config WpnService start= auto
    sc.exe config WpnUserService_????? start= auto
    sc.exe config PushToInstall start= demand
    sc.exe config WinRM start= disabled
    sc.exe config WSearch start= disabled
    sc.exe config WSService start= auto
    sc.exe config W32Time start= demand
    sc.exe config wuauserv start= demand
    sc.exe config WaaSMedicSvc start= demand
    sc.exe config WinHttpAutoProxySvc start= demand
    sc.exe config dot3svc start= demand
    sc.exe config WlanSvc start= demand
    sc.exe config wmiApSrv start= demand
    sc.exe config workfolderssvc start= disabled
    sc.exe config workfolderssvc start= disabled
    sc.exe config LanmanWorkstation start= auto
    sc.exe config W3SVC start= disabled
    sc.exe config WwanSvc start= disabled
    sc.exe config XboxGipSvc start= demand
    sc.exe config xbgm start= demand
    sc.exe config XblAuthManager start= disabled
    sc.exe config XblGameSave start= disabled
    sc.exe config XboxNetApiSvc start= disabled
    sc.exe config Browser start= disabled
    sc.exe config lltdsvc start= disabled
    sc.exe config PNRPsvc start= disabled
    sc.exe config p2psvc start= disabled
    sc.exe config p2pimsvc start= disabled
    sc.exe config PNRPAutoReg start= disabled
    sc.exe config wercplsupport start= disabled
    sc.exe config SSDPSRV start= disabled
    sc.exe config WMSVC start= disabled
    sc.exe config WerSvc start= disabled
    sc.exe config Wecsvc start= disabled
    sc.exe config WpnService start= disabled
    sc.exe config PushToInstall start= disabled
    sc.exe config XboxGipSvc start= disabled
    net start WinDefend
    net start WdNisSvc
    net start MpsSvc
    net stop WinRM
    Write-Host Completed configuring all services. -ForegroundColor Yellow -BackgroundColor Black
}

Write-Host "`n "
pause
select_func
}

select_func