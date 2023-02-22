# Non-Tech tips
+ Exam itself will not be too difficult, but time management, energy management, and mental adjustment makes it more difficult 
+ Never give up, meanwhile don't put too much time on a single box 
+ Don't rely on hint and walkthrough when practicing 
+ Don't make it complex, steps are usually simple 
+ Have a good rest and enough sleep!!! 
+ Enumerate, enumerate, and enumerate 
+ Apart from BoF + 10 points machine, rooting one 20 points machine is the key to pass 
+ Do not reply heavily on public exploit, misconfiguration can also be an approach 
+ From low-hanging fruits, such as SUID, sudo list, creds reuse, etc. 

# stuck in foothold

## web enum
+ Login/Credential is not always required. If need, use default credential or guess one, dictionary attack is rarely used. Sometime it can be found in documents such as article, review, source code or txt file, etc 
+ Hidden directory named by hostname, username, service name, or application's native path (such as GraphQL interface of Gatsby, CMS's sub-directory)  
+ curl -x POST --date "key=value" 10.10.10.10 
+ Info from content, such as posts, reviews, txt files, etc. 
+ SQLi and XSS are relatively uncommon but still could help 
+ Fuzz parameter to seek a potential commend injection entry; Guess parameters. If there's a POST forgot_pass.php with an email param, try GET /forgot_pass.php?email=%0aid.
  > Parameter/command injection fuzzing:
  > Payload list: github.com/payloadbox/command-injection-payload-list
  > `ffuf -w cmd-wordlist.txt -u 192.168.1.1/under_construction/forgot.php?email=abcdFUZZde`
  > See Proving Grounds' Hetemit for an example
+ More than one exploit to get a foothold. For example, one exploit helps RCE, RCE helps foothold 
+ Pay attention to OSINT, such as web content, especially user profile/bio section. It could contain credentials. Origination/Department name can also be username  
+ Enumerate all API endpoints, it could reveal sensitive info 
+ Fuzz each API endpoint to find command injection entry 
+ Edit HTML code in browser to recover hidden elements 
+ Use "1+1", "1*2" to verify eval() and other vulnerable function 
+ Use {{7*7}} to verify SSTI vulnerability 
  

## general
+ Framework and Plugins' exploit 
+ Reuse credential to log in any service you found, ssh/web/winrm/ftp/smb
+ Use captured username (from content, scanning results, etc.) to log in SSH with a weak password 
+ Docker containment environment and other rabbit holes 
+ Any service could have vuln and exploit, even if a relative robust service 
+ Apart from public exploits, misconfigurations could also be the entry 
+ UDP services, hidden port (FP of nmap) 
+ Client-side attack could help 
+ Use Svn/git tool to retrieve project files to analyze all files and source codes 
+ rdp port open, try login when you got password.
+ notice the hidden file, ftp/smb
+ notice the info and service you found, always connected. eg, you got password, rdp/ssh/win-rm/smb ans so on.

## RCE to shell
+ change the port
+ change the architure,x86/64
+ check the payload, param correct?
+ change the method, nc/bash/scripts/python and so on
+ rdp port open, try login when you got password.
+ notice the hidden file, ftp/smb
+ notice the info and service you found, always connected. eg, you got password, rdp/ssh/win-rm/smb and so on

# Privesc
+ Linpeas/Winpeas can find 90% PE vector, read output carefully 
+ Don't forget kernel exploit 
+ Third-Party program 
+ User's home folder/desktop, webroot, backups folder 
+ Writeable folder, file, service, etc. 
+ Locally listening port 
+ Description text file 
+ If there is one or more normal user accounts in server, it/they can help. Try to switch to it/one of them. 
+ Some programs run in GUI instead of command line, if RDP/VNC/X11Forwarding is enabled, always choose RDP/VNC/ssh -X rather than command line  
+ Check if any port is blocked by firewall (Will not be highlighted by PE script) 
+ Fuzz URL 
+ Check environment variables 
+ Pay attention to version control, make use of git and svn 

## linux privesc
+ use lse as a backup privesc tool.
+ File which is not presented in GTFOBins can also be exploited with some other conditions met 
+ Pay attention to wildcard 
+ Is current directory set noexec, nosuid? 
+ Use pspy to find hidden cronjobs and processes
+ Fully understand all functions of unfamiliar or custom sudo/SUID programs, use strings or cat to check its content 
+ sudo su, su root, su normaluser with reused password (web's login credential, other services' credential, etc), weak password. 
+ Check missing dynamic library of a file 
+ If a user is in a group, it's probably for a reason
+ If running as www-data, always inspect the contents of html or the application, look for commented out passwords.


## windows privesc
+ check the C:\ drive root. Some scheduled tasks can't be seen as a low level user could be located at C:\.
+ test a reverse shell on a windows box when attempting to get a shell.
+ Explore alternatives to a reverse shell. Leverage exposed remote access protocols. For example, if a reverse shell doesn't work, + execute a command to change the Administrator password and used smbexec to auth.
+ Identify all users. Attempt to brute force authentication via RDP
+ Always view "C:\program files" and "C:\program files (x86)" for installed apps.


# AD pratise
+ remember what you have done in the labs and try not to overthink things. You won't need any more knowledge than what you are given in the course.
+ stand-alone machine, enumerate everything you can.
+ Dont overthink it
+ Keep it simple
+ There is 3 machines on exam. Try to think why it is there :)
+ privesc and lateral movement are two different think!

# learn from practise
+ Credential reuse 
+ Communication/Connections between multiple ports/services 
+ Construct POST method, switch between POST and GET flexibly 
+ Dictionary attack/Brute-force attack is rarely used, default login or guessing a credential is more common, sometimes it is contained in documents. Login credential is not always required 
+ Multiple puzzles to complete an exploit 
+ If PE script does not work, typically manual enumeration is not hard 
+ Try kernel exploit last but do not forget this vector 
+ Linpeas/Winpeas can find 90% PE vector (especially in OSCP scope), read output carefully 
+ Collect info about hostname, username, webroot. 
+ Never look down on any service, even relative robust service (OpenSSH) could also has vulnerabilities and exploits 
+ Compared to exploit's title, its affected versions (such as CVE details) is more reliable. 
+ Use strings or cat to check unfamiliar file, especially custom files. 
+ Check backups folders and reuse credential 
+ More than one exploit needed. With exploit one, get important info (such as credential), the final exploit to get a shell 
+ Trails and errors, follow error messages and prompts 
+ shell cannot replace GUI 
+ Use fuzz to test existence of command injection entry 
+ Don't forget client-side attack, such as XSS, Phishing, etc 
+ Harvest credential from OSINT, such as public web contents 
+ Pay attention to targets' ports blocked by firewall 
+ Regular file's backup, such as /etc/crontab.bak 
+ Edit HTML code in browser by pressing F12 
+ Encoding can be something other than Base64 
+ Pay attention to user's home/desktop folder, and all files inside it, such as .bashrc 