# kali config for oscp

## zshrc config

### zsh alias

```bash
# config for vps use
export alivps=[ip]
export vpsip=$alivps
export ipnet=10.11.1
export win10ip=[ip]
alias ps7001='ps -aux | grep 7001'
alias sshconn='ssh -CfNg root@$vpsip -D 7001'
alias sshclose="ps -aux | grep -v grep | grep 7001 | tr -s ' ' | cut -d ' ' -f 2 | xargs kill"
alias scpconn='scp ~/ovpn/os-conn.tar.gz root@$alivps:/tmp'
alias sshvpn='sudo openvpn /home/kali/ovpn/ssh-lab.ovpn'
alias clashvpn='sudo openvpn /home/kali/ovpn/clash-lab.ovpn'
alias pingvps='ping -c 10 $vps'

alias connssh='ssh -CfNg root@$vps -D 7001'
alias closessh="ps -aux | grep -v grep | grep 7001 | tr -s ' ' | cut -d ' ' -f 2 | xargs kill"
alias scpconn='scp ~/ovpn/os-conn.tar.gz root@$alivps:/tmp'

# config for target
export kaliip=[ip]
export kip=[ip]
#export kip=10.11.73.77
#export kip=10.18.103.68
export tip=[ip]
export ippre=[ip]
export alivps=[ip]
export vps=$alivps

# my alias to common cmd
alias echok='echo $kip'
alias echot='echo $tip'
alias sedtip='changetarget(){sed -ir "s/^export tip=.*$/export tip=$1/g" ~/.zshrc;}; changetarget'
alias sedkip='changetarget(){sed -ir "s/^export kip=.*$/export kip=$1/g" ~/.zshrc;}; changetarget'
alias vimzsh='vim ~/.zshrc'
alias sourcezsh='source ~/.zshrc'

# tmux alias
alias tmn='tmux new -s'
alias tmd='tmux detach'
alias tma='tmux a -t'
alias tml='tmux ls'

# local tool alias
alias empire='/home/kali/ptw/Empire/empire'
alias kerbrute='/home/kali/ptw/kerbrute/kerbrute_linux_amd64'

# python change
alias py2='pyenv global 2.7.18'
alias py3='pyenv global 3.9.6'

# python web and apache
alias py2http='python -m SimpleHTTPServer 80 &'
alias py3http='python -m http.server 80 &'
alias closepyweb="ps -aux | grep -v grep | grep python | grep 80 | tr -s ' ' | cut -d ' ' -f 2 | xargs kill"
alias apachestart='sudo systemctl start apache2'
alias apachestop='sudo systemctl stop apache2'
alias apachestatus='sudo systemctl status apache2'
alias apacherestart='sudo systemctl restart apache2'

# proxychains
alias pxc='proxychains'

# smb share
alias smbshare='smbserver.py -smb2support share ./ &'
alias closesmb="ps -aux | grep -v grep | grep 'smbserver.py' | tr -s ' ' | cut -d ' ' -f 2 | xargs kill"

# scan command
alias openport='export port=$(cat nmap.light | grep ^[0-9] | cut -d "/" -f 1 | tr "\n" "," | sed s/,$//)'
#alias nmaplight='nmap --top-port=1000 --open -oN nmap.light'
alias nmaplight='nmap -p- -Pn --min-rate=500 -T4 --open -oN nmap.light'
#alias nmapheavy='sudo nmap -A -O -p- -sC -sV -T4 -oA nmap'
alias nmapheavy='openport && sudo nmap -A -O -Pn -p$port -sC -sV -T4 -oN nmap.heavy'
alias nmapsmbvuln='nmap --script=smb-vuln* -p 139,445 -oN smbvuln.nmap'
alias nmapscan='nmaplight $tip && openport && nmapheavy $tip'
alias nmapvuln='nmap --script vuln --min-rate=1000 -p$port -Pn $tip'

# offensive lab 
alias pinglab='ping -c 10 $ipnet.220'
alias rdeskwin10='proxychains rdesktop -g 90% -u administrator -p lab [ip]'
alias rdeskwin16='proxychains rdesktop -g 80% -u administrator -p lab [ip]'
alias rdeskdebian='proxychains rdesktop -g 80% -u root -p lab [ip]'
alias ssh44='ssh student@[ip]'

```

### alias from others

```bash
# nmap scan alias
alias nmapscan="nmap -sV -sC -p- -V"
## 提高效率的一些别名
alias httphere="python3 -m http.server 8000" #快速在当前目录搭建 http 服务，用于向目标主机上传文件
alias pingoscp="ping 10.11.1.8" # 用于测试 vpn 是否断开

## 使用 nmap 进行 mssql 漏洞利用
alias ttmssqlwithnmap="nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 " 
alias ttnmapsyn="sudo nmap -sV -sS -sC -p1-65535 --open -v" #快速进行 nmap 扫描
alias cdwordlists="cd /usr/share/wordlists/" # 快速进入 kali 字典

# 扫描系统服务
## 扫描 rdp 服务漏洞
alias ttrdpwithnmap="nmap --script \"rdp-enum-encryption or rdp-vuln-ms12-020 or rdp-ntlm-info\" -p 3389 -T4" 
alias ttsmb="nmap -A  --script=smb-vuln* -v --open" #使用nmap smb 脚本进行测试
alias ttsmbclient="sudo smbclient --option='client min protocol=NT1' -N -L"

# 扫描 Web 服务
## 使用 wpscan 扫描 wordpress 漏洞
alias ttwpscan="wpscan --enumerate ap,at,cb,dbe --url" 

## 使用大字典进行 Web 目录爆破
alias ttdirsearch-big="python3 /home/kali/githubtools/dirsearch/dirsearch.py -e php,jsp,asp -t 100 --random-agents -F -f -u" 
alias ttdirsearch-small-r="python3 /home/kali/githubtools/dirsearch/dirsearch.py -w /usr/share/dirb/wordlists/common.txt -e php,jsp,asp -t 100 -r -R 3 --random-agents -F -f -u" #使用小字典进行递归爆破 Web 目录
alias ttgobusterbig="gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x txt,html,htm,php -l -k -t 100 -r -u" #使用 gobuster 进行目录爆破
alias ttput="curl -v X OPTIONS" #测试目标主机支持的 http 方法

```

### zsh history merge
+ [askubuntu questions](https://askubuntu.com/questions/652305/how-can-i-transfer-my-bash-history-to-a-new-system)
+ [zsh builtin](https://gist.github.com/calexandre/63547c8dd0e08bf693d298c503e20aab), worked.

```bash
# not perfect.
sudo apt-get install moreutils
cat .bash_history.old $HISTFILE | sponge $HISTFILE

# zsh builtin to merge histroy.
builtin fc -R -I "$hist_file"
builtin fc -R -I "$another_hist_file"

# write the loaded history to HISTFILE
builtin fc -W "$HISTFILE"

```

## ssh-key login

```bash
# 1 密码可回车跳过，生成公私钥id_rsa id_rsa.pub
ssh-keygen -t rsa -b 4096  
ls ~/.ssh
# 2 copy公钥至server ~/.ssh/目录，命名为authorized_keys
ssh-copy-id -i /root/.ssh/id_rsa.pub root@servip
# 2 或 生成authorized_keys 写入公钥内容，已有文件可追加
touch authorized_keys
cat id_rsa.pub > authorized_keys
cat id_rsa.pub > authorized_keys  //追加

# 3 登录，-i指定私钥文件,默认.ssh路径下
ssh -i [id_rsa file] [user]@ip
ssh user@ip
```
## vpn no password

* openvpn快速连接

```bash
# 新建文件，auth.txt，第一行用户名，第二行密码
openvpn-username
openvpn-password

# 2.编辑.ovpn，在auth-user-pass后添加auth.txt
# 3.两个文件放在同目录
openvpn xx.ovpn

alias ovpn="sudo openvpn ~/ovpn/xxx.ovpn"
```

## kali autolock
取消自动锁屏
setting manager > power manager > security > automatically lock the session > never

## tmux
+ macos上iTerm2 + zsh, ssh连接kali；iTerm已支持分屏(Command+shift+D), 需重新建立kali session
+ iTerm2 配置tmux实现分屏（同session）
+ iTerm2 分屏是新建创建并使用原有session
+ [Tmux使用手册](http://louiszhai.github.io/2017/09/30/tmux/), 比较详细的使用、配置说明；
+ [github tmux cheatsheet](https://gist.github.com/ryerh/14b7c24dfd623ef8edc7)， 速查手册
+ ipsec tmux introduction video, [introduction to tmux](https://www.youtube.com/watch?v=Lqehvpe_djs&ab_channel=IppSec)
+ [Copy and paste in tmux](https://www.seanh.cc/2020/12/27/copy-and-paste-in-tmux/)
+ [Stuck in tmux scroll up](https://appuals.com/stuck-in-tmux-scroll-up/)

### tmux 安装
```bash
# macos
brew search tmux
brew install tmux

# linux
sudo apt install tmux

tmux -V
```

### 基本操作

```bash
# 启动新会话
tmux [new -s sessionname -n windowname]
tmux new -s demo

# 断开会话,会话后台运行
tmux detach

# 恢复会话
tmux at [-t sessionname]
tmux a # 默认进入第一个会话
tmux a -t demo # 进入demo会话

tmux ls

tmux kill-session -t 会话名
tmux kill-session -t demo # 关闭demo会话
tmux kill-server # 关闭服务器，所有的会话都将关闭

# 关闭所有会话
tmux ls | grep : | cut -d. -f1 | awk '{print substr($1, 0, length($1)-1)}' | xargs kill
```

Tmux 指令
> prefix, 默认`ctrl + b`

常用快捷方式

|系统指令|描述|
|:------|:------|
|? |显示快捷键帮助文档|
|d |断开当前会话|
|D |选择要断开的会话|
|Ctrl+z  |挂起当前会话|
|r |强制重载当前会话|
|s |显示会话列表用于选择并切换|
|: |进入命令行模式，此时可直接输入ls等命令|
|[ |进入复制模式，按q退出|
|] |粘贴复制模式中复制的文本|
|~ |列出提示信息缓存|
|**window相关**|描述|
|c |新建窗口|
|& |关闭当前窗口（关闭前需输入y or n确认）|
|0~9  |切换到指定窗口|
|p |切换到上一窗口|
|n |切换到下一窗口|
|w |打开窗口列表，用于且切换窗口|
|, |重命名当前窗口|
|. |修改当前窗口编号（适用于窗口重新排序）|
|f |快速定位到窗口（输入关键字匹配窗口名称）|
|**pane相关**|描述|
|" |当前面板上下一分为二，下侧新建面板|
|% |当前面板左右一分为二，右侧新建面板|
|x |关闭当前面板（关闭前需输入y or n确认）|
|z |最大化当前面板，再重复一次按键后恢复正常（v1.8版本新增）|
|! |将当前面板移动到新的窗口打开（原窗口中存在两个及以上面板有效）|
|; |切换到最后一次使用的面板|
|q |显示面板编号，在编号消失前输入对应的数字可切换到相应的面板|
|{ |向前置换当前面板|
|} |向后置换当前面板|
|Ctrl+o  |顺时针旋转当前窗口中的所有面板|
|方向键  |移动光标切换面板|
|o |选择下一面板|
|空格键  |在自带的面板布局中循环切换|
|Alt+方向键 |以5个单元格为单位调整当前面板边缘|
|Ctrl+方向键   |以1个单元格为单位调整当前面板边缘（Mac下被系统快捷键覆盖）|
|t |显示时钟|

常用配置
```bash
# 配置文件
~/.tmux.conf

# 修改默认prefix
set -g prefix C-a
unbind C-b # C-b即Ctrl+b键，unbind意味着解除绑定
bind C-a send-prefix # 绑定Ctrl+a为新的指令前缀

# 设置额外的prefix，tmux v1.6版起
set-option -g prefix2 `

# 配置文件生效, 重启tmux 或
# prefix + : # 进入命令模式
source-file ~/.tmux.conf

# bind key, reload conf
bind r source-file ~/.tmux.conf \; display-message "Config reloaded.."

# 修改快捷键, " % 为例
unbind '"'
bind - splitw -v -c '#{pane_current_path}' #上下分割 进入当前目录
unbind %
bind | splitw -h -c '#{pane_current_path}' #左右分割，进入当前目录

# 开启鼠标支持
# 鼠标选取文本、拖动调整pane大小、选中切换pane、选中切换window
set-option -g mouse on

```

## Macos iTerm2+Tmux
+ 参考[iTerm2 整合 Tmux 利器](https://blog.csdn.net/lvhdbb/article/details/95035743)

a. 配置iTerm2 Profile
iTerm2> Preferences > Profiles > xxprofile > General > Command, login shell, Send text at start

```bash
    tmux ls && read session && tmux -CC attach -t $session:-default} || tmux -CC new -s ${session:-default}

    tmux ls # 列出已有的tmux session。
    read session # 输入你需要打开的session。
    tmux -CC attact -t ${session:-default}  # 进入session。
    || tmux -CC new -s ${session:-default} # 如果session不存在则新建此session。
```

b. General 选项设置
  tmux Integration
    > 勾选 Auto
    > open tmux windows as native tabs in a new window

c. iTerm2 better setting
iTerm2> Preferences > Pointer
 > 勾选 Focus follows mouse, 选中的panel跟随鼠标

iTerm2> Preferences > Keys > Navigation shortcuts
设置切换pane tabs windows的快捷键

常用快捷键]

|Keys|作用|
|----|----|
|Command + T|新建Tab|
|Command + W|关闭选中panes, tab, window|
|Command + D|纵向分割选中的pane|
|Command + Shift + D|横向分割选中的pane|
|Command + Shift + Enter|最大化选中的pane,隐藏其它panes,再次按下就还原布局。|
|Command + ;|提示输入过的命令|
|Command + Shift + H|根据时间弹出历史记录|

## spf13-vim3

```bash
# install
curl https://j.mp/spf13-vim3 -L > spf13-vim.sh && sh spf13-vim.sh

# show linenum
```

## pyenv
+ kali 2022.3 默认使用python 版本为3.x，提供python2; kali 2020 默认提供python为2.x
+ 安装pyenv，管理多个python版本，配合virtualenv使用虚拟环境
+ 官方安装说明[kali install pyenv](https://www.kali.org/docs/general-use/using-eol-python-versions/)

```bash
sudo apt install -y build-essential libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev wget curl llvm libncurses5-dev libncursesw5-dev xz-utils tk-dev libffi-dev liblzma-dev python3-openssl git

curl https://pyenv.run | bash

# env config and path
echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.zshrc
echo 'export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.zshrc
echo -e 'if command -v pyenv 1>/dev/null 2>&1; then\n  eval "$(pyenv init --path)"\nfi' >> ~/.zshrc

## or add to zshrc
export PYENV_ROOT="$HOME/.pyenv"
export PATH="$PYENV_ROOT/bin:$PATH"
if command -v pyenv 1>/dev/null 2>&1; then
  eval "$(pyenv init -)"
fi
export PATH="/home/kali/.pyenv/shims:${PATH}"


exec $SHELL
pyenv  # check if  it works.

# if network issue, not able to down pyenv.run or git repo, try proxychains.

# usage 
pyenv versions
pyenv version

## install another python
pyenv install --list | grep 3.9
pyenv install 3.9.6
pyenv install 2.7.18

## change global
pyenv global 3.9.6
python -V
which python

## virtualenv 
pyenv virtualenv [version] <virtualenv-name> 
pyenv virtualenv 3.9.6 pt3
pyenv activate pt3
pyenv deactivate pt3

## install python error, ERROR: The Python ssl extension was not compiled. Missing the OpenSSL lib?
### https://github.com/pyenv/pyenv/wiki/Common-build-problems#error-the-python-ssl-extension-was-not-compiled-missing-the-openssl-lib
### check if you install libssl-dev, first step.
sudo apt install -y build-essential libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev wget curl llvm libncurses5-dev libncursesw5-dev xz-utils tk-dev libffi-dev liblzma-dev python3-openssl git
```
## sec tools

### common tool

```bash
# wordlist
sudo apt install seclists
sudo apt install wordlists --reinstall

# ad 
sudo apt install nishang
sudo apt install crackmapexec
sudo apt install evil-winrm

# web
sudo apt install feroxbuster
sudo apt install wpscan
sudo apt install gobuster
sudo apt install ffuf
sudo apt install html2markdown

# rdp 
sudo apt install rdesktop
sudo apt install xfreerdp
sudo apt install tsclient

# dns 
sudo apt install dig
sudo apt install knot-dnsutils
sudo apt install dnsutils

# windows compile
sudo apt install gcc-mingw-w64

## need to check and install, from https://mysecurityjournal.blogspot.com/p/client-side-attacks.html
sudo apt install mingw32 mingw-w64 mingw32-binutils tools

# oracle, odat
## https://github.com/quentinhardy/odat.git
## installation is complecated, rpm not support the arm64.
## install reference, git repo or htb silo vedio.
git clone https://github.com/quentinhardy/odat.git

# other
sudo apt install exiftool
sudo apt install libreoffice 
sudo apt install smtp-user-enum
```

### impacket-tool
+ [git repo](https://github.com/SecureAuthCorp/impacket)
+ kali默认已经安装，kali 2020 使用中可能有问题(impacket-psexec)，建议从git安装；
+ install reference, [install impacket](https://blog.eldernode.com/install-and-use-impacket-on-kali-linux/), [hacking artical install and use guide](https://www.hackingarticles.in/impacket-guide-smb-msrpc/)

```bash
# install
## clone to local dir,  sudo not necessary if use you home dir.
sudo git clone https://github.com/SecureAuthCorp/impacket.git /opt/impacket

## install, if default python is not 3, use pytho3
cd impacket
python3 ./setup install

## create virtualenv to install, which is recommended by git developer
pyenv virtualenv 3.9.6 pt3
pyenv activate pt3
## install requirement first.
pip install -r requirement.txt
python ./setup install
```

install error, [SSL: CERTIFICATE_VERIFY_FAILED] 
+ check [git issue](https://github.com/tox-dev/tox/issues/1273)
+ check stackoverflow, [ssl certificate failed](https://stackoverflow.com/questions/25981703/pip-install-fails-with-connection-error-ssl-certificate-verify-failed-certi)
+ or isntall requirement first.

Searching for dsinternals 
Reading https://pypi.org/simple/dsinternals/
Download error on https://pypi.org/simple/dsinternals/: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:997) -- Some packages may not be found!
Couldn't find index page for 'dsinternals' (maybe misspelled?)


### win buid

```bash
sudo apt update && sudo apt install wine32
sudo apt install wine
sudo apt install mingw-w64
sudo apt install gcc-multilib
```

## kali arm
+ [Guide to the 2022 OSCP Exam on M1 (with Active Directory)](https://medium.com/@GromHacks/guide-to-the-2022-oscp-exam-on-m1-with-active-directory-d8b4ce30f4f3)


### run x86
+ running x86 code on kali arm.[x86 on arm](https://www.kali.org/docs/arm/x86-on-arm/)

```bash
# run x86 code on arm
# https://www.kali.org/docs/arm/x86-on-arm/
sudo apt update
sudo apt install -y qemu-user-static binfmt-support

sudo dpkg --add-architecture amd64
sudo apt update
sudo apt install libc6:amd64

sudo apt install -y powershell

pwsh 

## run x86 code
qemu-x86_x64-static my_x86_code

```

### Kerbrute arm
+ [git repo](https://github.com/ropnop/kerbrute)
+ arm build, [git issue](https://github.com/ropnop/kerbrute/issues/50)

```bash
# instal golang
sudo apt install golang

# clone src
git clone https://github.com/ropnop/kerbrute.git
## or go get
go get github.com/ropnop/kerbrute

## build 
make all

## arm build
## modify makefile, add arm64
ARCHS=amd64 386 arm64

make linux

## go get error
## dial tcp 108.177.97.141:443: i/o timeout
go env -w GO111MODULE=on
go env -w GOPROXY=https://goproxy.cn,direct

make linux 
```

### cross compile
+ [cross compile question](https://www.quora.com/How-can-we-compile-the-x86-target-binaries-on-an-ARM-computer-from-C-C-source-code-Is-there-any-compilers-or-solutions-to-do-that)
+ [Cross compiling for arm or aarch64 on Debian or Ubuntu](https://jensd.be/1126/linux/cross-compiling-for-arm-or-aarch64-on-debian-or-ubuntu)

```bash
# cross compile winodes exp
## https://null-byte.wonderhowto.com/how-to/use-mingw-compile-windows-exploits-kali-linux-0179461/
apt install mingw-w64

## check the gcc
apt-cache search mingw-w64

## compile win exp
x86_64-w64-mingw32-gcc shell.c -o shell-64.exe
i686-w64-mingw32-gcc shell.c -o shell-32.exe

# cross compile linux x86 exp
sudo apt install gcc-i686-linux-gnu
sudo apt install gcc-x86-64-linux-gnu

## compile x86 32 bit
i686-linux-gnu-gcc -o setuid-x86 setuid.c

## compile x86_64
x86_64-linux-gnu-gcc setuid.c -o setuid-x86_64
```
