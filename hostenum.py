#!/usr/bin/env python3
"""
HostEnum — local privilege / system enumeration helper
D3F4UL7T

Collects host facts useful during authorized post-exploitation labs.
Linux primary. Windows via limited checks when run under WSL or remote.
Lab / authorized use only.
"""

from __future__ import annotations

import argparse
import os
import platform
import socket
import subprocess
import sys
from datetime import datetime
from pathlib import Path

VERSION = "1.0.0"

BANNER = r"""
   ______ _               _   ______
  / ____/(_)___  _________| | / ____/___  __  ______ ___
 / / __ / / __ \/ ___/ ___/ __ \ __/ / __ \/ / / / __ `__ \
/ /_/ // / /_/ (__  ) /__/ / / / /___/ / / / /_/ / / / / / /
\____//_/\____/____/\___/_/ /_/_____/_/ /_/\__,_/_/ /_/ /_/

  local system enumeration  |  D3F4UL7T
"""


def run(cmd: list[str] | str, timeout: float = 8.0, shell: bool = False) -> str:
    try:
        r = subprocess.run(
            cmd,
            shell=shell,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        out = (r.stdout or "") + (r.stderr or "")
        return out.strip()
    except Exception as e:
        return f"error: {e}"


def section(title: str) -> None:
    print(f"\n[{title}]")
    print("-" * 50)


def line(label: str, value: str) -> None:
    value = value.replace("\n", "\n" + " " * 14) if value else "-"
    print(f"  {label:12} {value}")


def enum_identity() -> None:
    section("identity")
    line("user", run(["whoami"]))
    line("id", run(["id"]))
    line("groups", run(["id", "-Gn"]))
    line("hostname", socket.gethostname())
    line("fqdn", socket.getfqdn())
    try:
        line("cwd", os.getcwd())
    except Exception:
        pass


def enum_system() -> None:
    section("system")
    line("os", f"{platform.system()} {platform.release()}")
    line("kernel", platform.version())
    line("machine", platform.machine())
    line("python", platform.python_version())
    if Path("/etc/os-release").exists():
        line("release", run(["cat", "/etc/os-release"]))
    line("uptime", run(["uptime"]))
    line("date", datetime.now().isoformat())


def enum_network() -> None:
    section("network")
    line("ifaces", run("ip -br a 2>/dev/null || ifconfig -a 2>/dev/null || ipconfig 2>/dev/null", shell=True))
    line("routes", run("ip r 2>/dev/null || route -n 2>/dev/null", shell=True))
    line("listen", run("ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null", shell=True))
    line("resolv", run(["cat", "/etc/resolv.conf"]) if Path("/etc/resolv.conf").exists() else "-")
    line("hosts", run(["cat", "/etc/hosts"]) if Path("/etc/hosts").exists() else "-")


def enum_users() -> None:
    section("users")
    if Path("/etc/passwd").exists():
        line("passwd", run(["cat", "/etc/passwd"]))
    if Path("/etc/group").exists():
        line("group", run(["cat", "/etc/group"]))
    line("sudo -l", run(["sudo", "-n", "-l"]))
    line("home", run(["ls", "-la", "/home"]))
    line("logged", run(["w"]))


def enum_procs() -> None:
    section("processes")
    line("ps", run(["ps", "auxf"]))
    line("cron", run("ls -la /etc/cron* 2>/dev/null; crontab -l 2>/dev/null", shell=True))
    line("systemd", run("systemctl list-units --type=service --state=running 2>/dev/null | head -40", shell=True))


def enum_suid() -> None:
    section("suid / capabilities")
    line("suid", run("find / -perm -4000 -type f 2>/dev/null | head -60", shell=True))
    line("sgid", run("find / -perm -2000 -type f 2>/dev/null | head -30", shell=True))
    line("caps", run("getcap -r / 2>/dev/null | head -40", shell=True))


def enum_files() -> None:
    section("interesting files")
    line("world-write", run("find / -xdev -type d -perm -0002 2>/dev/null | head -30", shell=True))
    line("ssh keys", run("find /home /root -name 'id_*' -o -name 'authorized_keys' 2>/dev/null | head -20", shell=True))
    line("history", run("ls -la ~/.bash_history ~/.zsh_history 2>/dev/null; tail -30 ~/.bash_history 2>/dev/null", shell=True))
    line("env", run(["env"]))
    if Path("/var/www").exists():
        line("www", run(["ls", "-la", "/var/www"]))


def enum_docker() -> None:
    section("containers")
    line("docker", run("docker ps -a 2>/dev/null || echo none", shell=True))
    line("cgroup", run(["cat", "/proc/1/cgroup"]) if Path("/proc/1/cgroup").exists() else "-")
    line(".dockerenv", "yes" if Path("/.dockerenv").exists() else "no")


def write_report(path: str, text: str) -> None:
    Path(path).write_text(text, encoding="utf-8")
    print(f"\n[+] report written: {path}")


def main() -> None:
    p = argparse.ArgumentParser(
        prog="hostenum",
        description="HostEnum — local system enumeration (D3F4UL7T)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python3 hostenum.py
  python3 hostenum.py --quick
  python3 hostenum.py --no-suid --out report.txt
        """,
    )
    p.add_argument("--quick", action="store_true", help="skip heavy find/suid scans")
    p.add_argument("--no-suid", action="store_true", help="skip suid/capability search")
    p.add_argument("--no-procs", action="store_true", help="skip process listing")
    p.add_argument("--out", "-o", help="write full stdout capture to file")
    p.add_argument("--version", action="version", version=f"HostEnum {VERSION}")
    args = p.parse_args()

    # capture output if requested
    buf: list[str] = []
    if args.out:
        class Tee:
            def write(self, s: str) -> int:
                buf.append(s)
                return sys.__stdout__.write(s)
            def flush(self) -> None:
                sys.__stdout__.flush()
        sys.stdout = Tee()  # type: ignore

    print(BANNER)
    print(f"[*] HostEnum {VERSION}")
    print("[!] authorized lab use only\n")

    enum_identity()
    enum_system()
    enum_network()
    enum_users()

    if not args.no_procs and not args.quick:
        enum_procs()
    if not args.no_suid and not args.quick:
        enum_suid()
    if not args.quick:
        enum_files()
        enum_docker()

    print(f"\n[*] done {datetime.now().isoformat()}")

    if args.out:
        sys.stdout = sys.__stdout__
        write_report(args.out, "".join(buf))


if __name__ == "__main__":
    main()
