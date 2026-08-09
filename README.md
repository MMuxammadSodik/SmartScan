# SmartScan

**Automated recon helper for pentesters.**

SmartScan wraps `nmap` and layers on the recon steps you'd normally do by hand
right after it finishes: OS fingerprinting, web framework detection
(Tomcat, Jenkins, Gogs, Gitea, ...), null/anonymous session checks on common
services, DNS zone enumeration (including AXFR attempts), lightweight HTTP
endpoint fuzzing, and time-bounded virtual host discovery.

```
------------
   0xM4IX
------------
```

## Features

- **Nmap wrapper** — runs `-sV -sC -Pn -T4 --min-rate=1000 [-O]`, parses the
  output, and reuses a valid `nmap-scan.txt` from a previous run against the
  same target instead of re-scanning.
- **OS fingerprinting** — combines nmap's OS guess with open-port/service
  heuristics as a fallback.
- **Web framework detection** — regex-based signature matching against
  headers/body for common frameworks and admin panels.
- **Null/anonymous session checks** — SMB, FTP, RPC, and more.
- **DNS enumeration** — runs the ANY/A/AAAA/NS/SOA/MX/TXT/PTR equivalent of
  `dig @<target> <zone> ANY`, attempts AXFR against discovered nameservers,
  and — if you don't know the zone — infers it automatically from LDAP/
  Kerberos service banners nmap picks up on domain controllers.
- **HTTP endpoint enumeration** — checks a built-in list of common
  admin/API/framework paths against discovered web ports.
- **VHost fuzzing** — time-bounded virtual host brute force with automatic
  noise filtering: it doesn't just diff against one random baseline request,
  it tracks the most common response signature across the whole run and
  filters it out automatically (the same effect as running `ffuf`, eyeballing
  the repeated response size, then re-running with `-fs/-fw <size>` —
  done in one pass). Malformed wordlist entries (`-`, `%20`, `*checkout*`,
  etc.) are skipped before they're ever sent, since they trigger false-positive
  400s regardless of the target.

## Requirements

- Python 3.8+
- `nmap` on `PATH` (root recommended, for `-O` OS detection)
- `dig` on `PATH` (for DNS enumeration)
- Python packages: `requests`, optionally `paramiko` and `colorama`

```bash
pip install requests paramiko colorama
```

## Usage

```
SmartScan.py -H <target_ip> <options>

Options:
  -H <target_ip>          Target host to scan (required)
  -vhost <hostname>       Base hostname to use for vhost scanning
  -vhost-list <path>      Wordlist for vhost scanning
                           e.g. /usr/share/dirbuster/wordlists/dirbuster.txt
  -vhost-time <seconds>   Maximum vhost fuzzing time (default: 240)
                           Fuzzing stops after this long even if the
                           wordlist isn't exhausted.
  -p <ports>              Restrict nmap to specific ports/ranges (optional)
  -h, --help              Show this help message and exit
```

If neither `-vhost` nor any other option is given, SmartScan simply runs a
smart recon scan: nmap → OS guess → open ports → null/anon session checks on
common services.

### Examples

Basic recon:

```bash
python3 smartscan.py -H 10.10.10.10
```

Recon + vhost fuzzing against a known zone, capped at 5 minutes:

```bash
python3 smartscan.py -H 10.10.10.10 \
  -vhost danglingtree.htb \
  -vhost-list /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt \
  -vhost-time 300
```

Restrict nmap to specific ports (skips the cached `nmap-scan.txt`, since the
requested scope may differ):

```bash
python3 smartscan.py -H 10.10.10.10 -p 80,443,3389
```

## Output

- `nmap-scan.txt` — raw `nmap -oN` output, reused on subsequent runs against
  the same target (unless `-p` is passed).
- Everything else prints straight to the terminal, organized by section
  (Open Ports, DNS Enumeration, HTTP Endpoints, OS guess, Null/Anon Sessions,
  VHost Scanning).

## Disclaimer

This tool is intended for authorized security testing and CTF/lab
environments (e.g. HackTheBox, TryHackMe) only. Only run it against systems
you own or have explicit written permission to test. The author takes no
responsibility for misuse.
