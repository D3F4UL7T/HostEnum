# HostEnum

Local system enumeration for authorized post-exploitation labs.

D3F4ULT

Collects host identity, network state, users, processes, SUID/capabilities, and other high-signal facts in one pass. Linux primary.

## Install

```bash
git clone https://github.com/D3F4UL7T/HostEnum.git
cd HostEnum
python3 hostenum.py --help
```

Python 3.8+. No external dependencies.

## Usage

```bash
python3 hostenum.py
python3 hostenum.py --quick
python3 hostenum.py --no-suid
python3 hostenum.py -o report.txt
```

## Coverage

| Section | Content |
|---------|---------|
| identity | user, groups, hostname, cwd |
| system | OS, kernel, machine, uptime |
| network | interfaces, routes, listeners, resolv, hosts |
| users | passwd, group, sudo -l, home, logged-in |
| processes | ps, cron, running units |
| suid | SUID/SGID binaries, file capabilities |
| files | world-writable dirs, SSH keys, history, env |
| containers | docker presence, cgroup, .dockerenv |

## Notes

Companion to [OffKit](https://github.com/D3F4UL7T/OffKit).

Lab and authorized use only. Unauthorized access is illegal. Author assumes no liability for misuse.
