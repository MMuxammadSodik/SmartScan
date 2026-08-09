#!/usr/bin/env python3
"""
SmartScan - Automated recon helper for pentesters.

Wraps nmap, does OS fingerprint heuristics, flags obvious web frameworks
(Tomcat/Gogs/Jenkins/etc.), checks common services for null/anonymous
sessions, and (optionally) brute-forces virtual hosts on discovered web
ports.

Author: you. License: whatever you put in the repo.
"""

import argparse
import concurrent.futures
import ftplib
import os
import random
import re
import shutil
import socket
import string
import subprocess
import sys
import ipaddress
import time
import threading
import io
import contextlib
import collections

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    requests = None

try:
    import paramiko
except ImportError:
    paramiko = None

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
except ImportError:
    class _NoColor:
        def __getattr__(self, _):
            return ""
    Fore = _NoColor()
    Style = _NoColor()


# --------------------------------------------------------------------------- #
# Banner
# --------------------------------------------------------------------------- #

BANNER = r"""
------------
   0xM4IX
------------
"""


def print_banner():
    print(f"{Fore.BLUE}{Style.BRIGHT}{BANNER}{Style.RESET_ALL}")


# --------------------------------------------------------------------------- #
# Pretty printing helpers  (green = success, red = failure, blue = info)
# --------------------------------------------------------------------------- #

def info(msg):
    print(f"{Fore.BLUE}[*]{Style.RESET_ALL} {msg}")


def good(msg):
    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")


def warn(msg):
    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")


def bad(msg):
    print(f"{Fore.RED}[-]{Style.RESET_ALL} {msg}")


def section(title):
    print()
    print(f"{Fore.BLUE}{Style.BRIGHT}{title}{Style.RESET_ALL}")


def bold(msg):
    return f"{Style.BRIGHT}{msg}{Style.RESET_ALL}"


# --------------------------------------------------------------------------- #
# Live spinner (used for long-running/blocking calls like nmap and dig)
# --------------------------------------------------------------------------- #

_SPINNER_FRAMES = "|/-\\"


def _clear_line():
    sys.__stdout__.write("\r" + " " * 100 + "\r")
    sys.__stdout__.flush()


def _spinner_loop(stop_event, message):
    start = time.monotonic()
    i = 0
    while not stop_event.is_set():
        elapsed = time.monotonic() - start
        frame = _SPINNER_FRAMES[i % len(_SPINNER_FRAMES)]
        sys.__stdout__.write(
            f"\r{Fore.BLUE}[{frame}]{Style.RESET_ALL} {bold(message)} "
            f"({elapsed:0.0f}s)"
        )
        sys.__stdout__.flush()
        i += 1
        stop_event.wait(0.15)
    _clear_line()


def run_with_spinner(message, func, *args, **kwargs):
    """
    Runs `func(*args, **kwargs)` on a worker thread while showing a live
    spinner + elapsed-time counter on the current terminal line. Re-raises
    whatever `func` raised; returns whatever `func` returned.
    """
    stop_event = threading.Event()
    outcome = {}

    def _worker():
        try:
            outcome["value"] = func(*args, **kwargs)
        except BaseException as exc:  # noqa: BLE001 - re-raised on the caller's thread
            outcome["error"] = exc

    spinner_thread = threading.Thread(target=_spinner_loop, args=(stop_event, message))
    worker_thread = threading.Thread(target=_worker)

    spinner_thread.start()
    worker_thread.start()
    worker_thread.join()
    stop_event.set()
    spinner_thread.join()

    if "error" in outcome:
        raise outcome["error"]
    return outcome.get("value")


# --------------------------------------------------------------------------- #
# Web-service signature fingerprints
# (very rough heuristics — nmap's -sC/-sV already do the heavy lifting,
#  this just adds a couple of extra guesses based on headers/body)
# --------------------------------------------------------------------------- #

WEB_SIGNATURES = {
    "Tomcat":     [r"apache tomcat", r"coyote"],
    "Gogs":       [r"gogs", r"go-git"],
    "Gitea":      [r"gitea"],
    "Jenkins":    [r"x-jenkins", r"jenkins"],
    "phpMyAdmin": [r"phpmyadmin"],
    "WordPress":  [r"wp-content", r"wp-includes"],
    "Joomla":     [r"joomla"],
    "Drupal":     [r"drupal"],
    "GitLab":     [r"gitlab"],
    "Nexus":      [r"nexus repository"],
    "Jira":       [r"atlassian jira", r"jira"],
    "Confluence": [r"atlassian confluence"],
    "Grafana":    [r"grafana"],
    "Kibana":     [r"kibana"],
    "Webmin":     [r"webmin"],
    "IIS ASP.NET": [r"asp\.net", r"x-aspnet-version"],
}


def fingerprint_web_service(host, port, use_ssl):
    """Best-effort HTTP probe for a friendlier service name than nmap gives."""
    if requests is None:
        return None
    scheme = "https" if use_ssl else "http"
    url = f"{scheme}://{host}:{port}/"
    try:
        r = requests.get(url, timeout=6, verify=False, allow_redirects=True)
    except Exception:
        return None

    blob = " ".join([
        r.headers.get("Server", ""),
        r.headers.get("X-Powered-By", ""),
        str(r.headers),
        r.text[:4000] if r.text else "",
    ]).lower()

    hits = []
    for name, patterns in WEB_SIGNATURES.items():
        for pat in patterns:
            if re.search(pat, blob):
                hits.append(name)
                break
    return hits[0] if hits else None


# --------------------------------------------------------------------------- #
# Nmap  (plain-text -oN output only, no XML)
# --------------------------------------------------------------------------- #

class NmapResult:
    def __init__(self):
        self.ports = []          # list of dicts: port, proto, service, tunnel, info
        self.os_guesses = []     # list of (name, accuracy_str)
        self.raw_txt_path = None


PORT_LINE_RE = re.compile(r'^(\d+)/(tcp|udp)\s+(\S+)\s+(\S+)(?:\s+(.*))?$')
OS_DETAILS_RE = re.compile(r'^OS details:\s*(.+)$', re.MULTILINE)
OS_AGGRESSIVE_RE = re.compile(r'^Aggressive OS guesses:\s*(.+)$', re.MULTILINE)
OS_GUESS_ENTRY_RE = re.compile(r'(.+?)\s*\((\d+)%\)')
OS_RUNNING_RE = re.compile(r'^Running:\s*(.+)$', re.MULTILINE)


def check_nmap_installed():
    if shutil.which("nmap") is None:
        bad("nmap was not found on PATH. Install it (e.g. `apt install nmap`) and try again.")
        sys.exit(1)


def cached_nmap_result(target, path="nmap-scan.txt"):
    """
    Reuse nmap-scan.txt when it is a valid Nmap report for the requested
    target. Nmap may identify a host as either an IP or:
        Nmap scan report for hostname (IP)
    so both forms are accepted.
    """
    if not os.path.isfile(path):
        return None

    try:
        with open(path, "r", errors="ignore") as f:
            text = f.read()
    except OSError:
        return None

    if not text.startswith("# Nmap"):
        return None

    # Extract the actual target from Nmap's report line.
    report_match = re.search(
        r"^Nmap scan report for (.+?)(?: \(([^)]+)\))?$",
        text,
        re.MULTILINE,
    )

    if not report_match:
        return None

    reported_name = report_match.group(1).strip()
    reported_ip = (report_match.group(2) or "").strip()

    target = target.strip()

    # Accept:
    #   target == reported_name
    #   target == reported_ip
    #   target resolves to the report's IP
    target_matches = (
        target == reported_name
        or target == reported_ip
    )

    if not target_matches:
        try:
            target_ips = {
                info[4][0]
                for info in socket.getaddrinfo(
                    target, None, socket.AF_UNSPEC, socket.SOCK_STREAM
                )
            }
            target_matches = reported_ip in target_ips
        except socket.gaierror:
            pass

    if not target_matches:
        warn(
            f"nmap-scan.txt exists, but it appears to belong to "
            f"'{reported_name}' ({reported_ip or 'unknown IP'}), not '{target}'."
        )
        return None

    if "PORT" not in text or "Nmap done at" not in text:
        warn("nmap-scan.txt exists but does not look like a complete Nmap report.")
        return None

    result = NmapResult()
    result.raw_txt_path = path
    result.ports = parse_ports_from_text(text)
    result.os_guesses = parse_os_from_text(text)

    info("nmap-scan.txt was found and matches the target — skipping Nmap scan.")
    return result


def run_nmap(target, ports=None, out_basename="nmap-scan"):
    """
    Runs nmap with service/version detection + default scripts + OS
    detection, writes nmap-scan.txt (human readable, -oN only), and
    returns a populated NmapResult parsed from that text file.
    """
    check_nmap_installed()

    txt_path = f"{out_basename}.txt"

    cmd = ["nmap", "-sV", "-sC", "-Pn", "-T4", "--min-rate=1000"]

    # OS detection needs root; try it, nmap will just warn and continue
    # (as non-root) rather than hard fail on most systems.
    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    if is_root:
        cmd.append("-O")
    else:
        warn("Not running as root — OS detection (-O) and some scripts may be skipped/less accurate. "
             "Consider running with sudo for best results.")

    if ports:
        cmd += ["-p", ports]

    cmd += ["-oN", txt_path, target]

    info("Running Nmap Scan...")

    def _do_scan():
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

    try:
        run_with_spinner("Running Nmap scan...", _do_scan)
    except subprocess.CalledProcessError as e:
        bad(f"nmap failed: {e.stderr.decode(errors='ignore') if e.stderr else e}")
        sys.exit(1)
    except FileNotFoundError:
        bad("nmap binary not found.")
        sys.exit(1)

    if not os.path.exists(txt_path):
        bad("nmap did not produce an output file to parse — bailing out.")
        sys.exit(1)

    with open(txt_path, "r", errors="ignore") as f:
        text = f.read()

    result = NmapResult()
    result.raw_txt_path = txt_path
    result.ports = parse_ports_from_text(text)
    result.os_guesses = parse_os_from_text(text)
    return result


def parse_ports_from_text(text):
    ports = []
    for line in text.splitlines():
        m = PORT_LINE_RE.match(line.strip())
        if not m:
            continue
        port, proto, state, service_token, rest = m.groups()
        if state != "open":
            continue

        tunnel = ""
        base_service = service_token

        if base_service.startswith("ssl/"):
            tunnel = "ssl"
            base_service = base_service[4:]
        elif base_service.lower() == "https":
            tunnel = "ssl"
            base_service = "http"
        elif base_service.lower() == "ssl":
            tunnel = "ssl"
            base_service = "unknown"

        uncertain = base_service.endswith("?")
        base_service = base_service.rstrip("?")

        ports.append({
            "port": int(port),
            "proto": proto,
            "service": base_service.lower(),
            "tunnel": tunnel,
            "uncertain": uncertain,
            "info": (rest or "").strip(),
        })
    return ports


def parse_os_from_text(text):
    guesses = []

    m = OS_DETAILS_RE.search(text)
    if m:
        guesses.append((m.group(1).strip(), "100"))
        return guesses

    m = OS_AGGRESSIVE_RE.search(text)
    if m:
        for entry in m.group(1).split(","):
            mm = OS_GUESS_ENTRY_RE.match(entry.strip())
            if mm:
                guesses.append((mm.group(1).strip(), mm.group(2)))
        if guesses:
            return guesses

    m = OS_RUNNING_RE.search(text)
    if m:
        guesses.append((m.group(1).strip(), "n/a"))

    return guesses


def format_service_line(p):
    """Builds the 'PORT - SERVICE info' display line."""
    if p["tunnel"] == "ssl" and p["service"] == "http":
        label = "HTTPS"
    else:
        label = (p["service"] or "unknown").upper()

    line = f"{p['port']} - {label}"
    if p["info"]:
        line += f" {p['info']}"
    return line


# --------------------------------------------------------------------------- #
# OS fingerprint heuristic
# --------------------------------------------------------------------------- #

WINDOWS_HINT_PORTS = {135, 139, 445, 3389, 5985, 5986}
WINDOWS_HINT_SERVICES = {"microsoft-ds", "netbios-ssn", "msrpc", "ms-wbt-server"}
LINUX_HINT_SERVICES = {"ssh"}


def guess_os(nmap_result):
    # 1. trust nmap's own OS detection if it produced anything decent
    if nmap_result.os_guesses:
        top_name, top_acc = nmap_result.os_guesses[0]
        low = top_name.lower()
        if "windows" in low:
            return "Windows", f"nmap OS detection ({top_name}, {top_acc}% confidence)"
        if "linux" in low or "unix" in low:
            return "Linux", f"nmap OS detection ({top_name}, {top_acc}% confidence)"

    # 2. fall back to port/service heuristics
    open_ports = {p["port"] for p in nmap_result.ports}
    open_services = {(p["service"] or "").lower() for p in nmap_result.ports}
    info_blob = " ".join((p["info"] or "") for p in nmap_result.ports).lower()

    windows_score = len(open_ports & WINDOWS_HINT_PORTS) + len(open_services & WINDOWS_HINT_SERVICES)
    if "windows" in info_blob:
        windows_score += 2

    linux_score = len(open_services & LINUX_HINT_SERVICES)
    if "ubuntu" in info_blob or "debian" in info_blob or "linux" in info_blob:
        linux_score += 2

    if windows_score > linux_score:
        return "Windows", "port/service heuristic"
    if linux_score > windows_score:
        return "Linux", "port/service heuristic"
    return "Unknown", "insufficient signal"


# --------------------------------------------------------------------------- #
# Null / anonymous session checks
#
# Each checker returns a (status, detail) tuple:
#   status: "SUCCESS" | "FAILED" | "SKIPPED"
#   detail: optional extra string (reason / error), or None
# --------------------------------------------------------------------------- #

def check_ssh_null(host, port):
    if paramiko is None:
        return ("SKIPPED", "paramiko not installed")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, port=port, username="", password="", timeout=6,
                        allow_agent=False, look_for_keys=False)
        return ("SUCCESS", None)
    except paramiko.AuthenticationException:
        return ("FAILED", None)
    except (paramiko.SSHException, socket.error, EOFError) as e:
        return ("FAILED", str(e))
    finally:
        try:
            client.close()
        except Exception:
            pass


def check_ftp_anonymous(host, port):
    try:
        ftp = ftplib.FTP()
        ftp.connect(host, port, timeout=6)
        ftp.login("anonymous", "anonymous@")
        ftp.quit()
        return ("SUCCESS", None)
    except ftplib.error_perm:
        return ("FAILED", None)
    except Exception as e:
        return ("FAILED", str(e))


def check_smb_null(host, port):
    if shutil.which("smbclient") is None:
        return ("SKIPPED", "smbclient not installed")
    cmd = ["smbclient", "-L", f"//{host}", "-N", "-m", "SMB3"]
    try:
        out = subprocess.run(cmd, capture_output=True, timeout=15, text=True)
        combined = (out.stdout + out.stderr).lower()
        if "session setup failed" in combined or "nt_status_access_denied" in combined \
                or "nt_status_logon_failure" in combined:
            return ("FAILED", None)
        if "sharename" in combined or "server" in combined:
            return ("SUCCESS", None)
        return ("FAILED", combined.strip()[:80] or None)
    except subprocess.TimeoutExpired:
        return ("FAILED", "timeout")
    except Exception as e:
        return ("FAILED", str(e))


def check_rpc_null(host, port):
    if shutil.which("rpcclient") is None:
        return ("SKIPPED", "rpcclient not installed")
    cmd = ["rpcclient", "-U", "", "-N", host, "-c", "srvinfo"]
    try:
        out = subprocess.run(cmd, capture_output=True, timeout=15, text=True)
        combined = (out.stdout + out.stderr).lower()
        if "nt_status_access_denied" in combined:
            return ("FAILED", "access denied")
        if "nt_status_logon_failure" in combined or "nt_status_connection_refused" in combined:
            return ("FAILED", None)
        if "platform_id" in combined or "server type" in combined or (out.returncode == 0 and combined.strip()):
            return ("SUCCESS", None)
        return ("FAILED", None)
    except subprocess.TimeoutExpired:
        return ("FAILED", "timeout")
    except Exception as e:
        return ("FAILED", str(e))


# service-name -> (checker function, matching nmap service tokens)
NULL_SESSION_CHECKS = [
    ("SSH", {"ssh"}, check_ssh_null),
    ("FTP", {"ftp"}, check_ftp_anonymous),
    ("SMB", {"microsoft-ds", "netbios-ssn"}, check_smb_null),
    ("RPC", {"msrpc"}, check_rpc_null),
]


def report_null_session_result(label, status, detail):
    if status == "SUCCESS":
        good(f"{label} -> Anonymous Login Successful!")
    elif status == "SKIPPED":
        warn(f"{label} -> SKIPPED ({detail})")
    else:
        msg = f"{label} -> FAILED!"
        if detail:
            msg += f" ({detail})"
        bad(msg)


def run_null_session_checks(host, nmap_result):
    section("Scanning For Null/Anonymous Sessions in services!")
    seen_labels = set()
    open_services = {(p["service"] or "").lower(): p for p in nmap_result.ports}

    for label, service_names, checker in NULL_SESSION_CHECKS:
        match = next((svc for svc in service_names if svc in open_services), None)
        if not match or label in seen_labels:
            continue
        seen_labels.add(label)
        port = open_services[match]["port"]
        status, detail = checker(host, port)
        report_null_session_result(label, status, detail)


# --------------------------------------------------------------------------- #
# DNS enumeration
# --------------------------------------------------------------------------- #

DNS_RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT", "PTR", "SRV")


def _run_dig(args, server=None, timeout=8):
    """Run dig and return stdout. server is passed as @server."""
    if shutil.which("dig") is None:
        return None

    cmd = ["dig"]
    if server:
        cmd.append(f"@{server}")
    cmd.extend(args)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode != 0:
            return None

        # +short is intentionally NOT used here. Keeping the full response
        # makes DNS enumeration reliable for ANY and easier to troubleshoot.
        return result.stdout.strip()
    except (subprocess.TimeoutExpired, OSError):
        return None


def infer_domain_from_nmap(nmap_result):
    """
    Best-effort extraction of an AD/DNS domain name from nmap service info.

    nmap's LDAP/Kerberos probes commonly surface the domain directly, e.g.:
        Microsoft Windows Active Directory LDAP (Domain: danglingtree.htb, ...)
    This is a very reliable source of the zone name on domain controllers,
    and doesn't require a working PTR record.
    """
    if nmap_result is None:
        return None

    for p in nmap_result.ports:
        info_str = p.get("info") or ""
        match = re.search(r"Domain:\s*([A-Za-z0-9.-]+\.[A-Za-z]{2,})", info_str)
        if match:
            return match.group(1).rstrip(".")

    return None


def infer_dns_name(host, explicit_hostname=None, nmap_result=None):
    """
    Prefer an explicitly supplied hostname; otherwise try reverse DNS,
    then fall back to a domain name harvested from nmap's service info
    (e.g. LDAP/Kerberos banners on a domain controller).
    """
    if explicit_hostname:
        return explicit_hostname.rstrip(".")

    try:
        ip = ipaddress.ip_address(host)
        reverse = ip.reverse_pointer
        ptr = _run_dig([reverse, "PTR"], server=host)
        if ptr:
            return ptr.splitlines()[0].rstrip(".")
    except ValueError:
        pass

    try:
        return socket.gethostbyaddr(host)[0].rstrip(".")
    except (socket.herror, socket.gaierror, OSError):
        pass

    return infer_domain_from_nmap(nmap_result)


def enumerate_dns(host, hostname=None, nmap_result=None):
    """
    Query the discovered DNS server directly.

    Equivalent to:
        dig @<host> <hostname> ANY

    This is important for HTB/internal DNS where the target itself is the
    authoritative/resolver server. When no hostname is supplied and reverse
    DNS comes up empty, the domain is inferred from nmap's LDAP/Kerberos
    service banners (common on AD domain controllers) before giving up.
    """
    section("DNS Enumeration")

    if shutil.which("dig") is None:
        warn("DNS port is open, but `dig` is not installed.")
        return

    dns_name = infer_dns_name(host, hostname, nmap_result)

    if not dns_name:
        warn("Could not determine a DNS hostname.")
        warn("Use -vhost <hostname> to provide the DNS hostname/zone.")
        return

    if not hostname:
        info(f"No -vhost given; inferred DNS zone '{dns_name}' automatically.")

    info(f"DNS server: {host}")
    info(f"DNS name: {dns_name}")

    def _gather_and_print():
        found = False

        # Exact equivalent of:
        # dig @10.129.56.71 danglingtree.htb ANY
        any_output = _run_dig(
            [dns_name, "ANY", "+time=3", "+tries=1"],
            server=host,
            timeout=6,
        )

        if any_output:
            found = True
            print("Records:")
            in_answer = False
            in_additional = False

            for line in any_output.splitlines():
                stripped = line.strip()

                if stripped == ";; ANSWER SECTION:":
                    in_answer = True
                    in_additional = False
                    continue

                if stripped == ";; ADDITIONAL SECTION:":
                    in_answer = False
                    in_additional = True
                    continue

                if stripped.startswith(";;"):
                    continue

                # Print actual ANSWER and ADDITIONAL records.
                if in_answer or in_additional:
                    if stripped:
                        print(f"  {stripped}")

            # If dig returned something unusual without normal sections, don't
            # hide it; show the output so enumeration is diagnosable.
            if ";; ANSWER SECTION:" not in any_output:
                for line in any_output.splitlines():
                    if line.strip() and not line.startswith(";;"):
                        print(f"  {line.strip()}")

        # Query individual record types as a fallback/complement to ANY.
        for record_type in DNS_RECORD_TYPES:
            if record_type == "PTR":
                continue

            output = _run_dig(
                [dns_name, record_type, "+short", "+time=2", "+tries=1"],
                server=host,
                timeout=5,
            )

            if not output:
                continue

            values = [
                line.strip()
                for line in output.splitlines()
                if line.strip() and not line.startswith(";;")
            ]

            if values:
                found = True
                print(f"{record_type}:")
                for value in values:
                    print(f"  {value}")

        # Reverse DNS of the DNS server.
        try:
            ip = ipaddress.ip_address(host)
            reverse = ip.reverse_pointer
            ptr = _run_dig(
                [reverse, "PTR", "+short", "+time=2", "+tries=1"],
                server=host,
                timeout=5,
            )
            if ptr:
                print("PTR:")
                for line in ptr.splitlines():
                    if line.strip():
                        print(f"  {line.strip()}")
                found = True
        except ValueError:
            pass

        # Try AXFR against discovered authoritative nameservers.
        ns_output = _run_dig(
            [dns_name, "NS", "+short", "+time=2", "+tries=1"],
            server=host,
            timeout=5,
        )

        if ns_output:
            for ns in ns_output.splitlines():
                ns = ns.strip().rstrip(".")
                if not ns:
                    continue

                axfr = _run_dig(
                    [dns_name, "AXFR", "+time=3", "+tries=1"],
                    server=ns,
                    timeout=8,
                )

                if axfr and "Transfer failed" not in axfr:
                    good(f"AXFR allowed by {ns}!")
                    print(axfr)
                    found = True

        if not found:
            warn("No DNS records were returned by the discovered DNS server.")

    # Buffer all the printing above so it doesn't collide with the spinner
    # writing to the terminal; flush it once the queries are done.
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        run_with_spinner("Querying DNS records...", _gather_and_print)
    sys.stdout.write(buffer.getvalue())


# --------------------------------------------------------------------------- #
# HTTP endpoint enumeration and application fingerprinting
# --------------------------------------------------------------------------- #

DEFAULT_ENDPOINTS = [
    "robots.txt", "sitemap.xml", ".well-known/security.txt",
    "login", "admin", "administrator", "dashboard",
    "wp-admin", "wp-login.php", "wp-content/", "wp-includes/",
    "xmlrpc.php", "server-status", "manager/html",
    "host-manager/html", "jenkins/", "gogs/", "gitea/",
    "gitlab/", "grafana/", "kibana/", "phpmyadmin/",
    "api/", "api/v1/", "swagger/", "swagger-ui/",
    "swagger-ui.html", "openapi.json", "actuator/", "actuator/health",
    "console/", "web-console/", "login.jsp", "index.php",
    ".git/HEAD", ".env", "config/", "backup/", "backups/",
    "uploads/", "files/", "static/", "assets/"
]

WEB_FINGERPRINT_PATTERNS = {
    "WordPress": [r"wp-content", r"wp-includes", r"wp-json"],
    "Tomcat": [r"apache tomcat", r"coyote", r"tomcat"],
    "Gogs": [r"\bgogs\b"],
    "Gitea": [r"\bgitea\b"],
    "Jenkins": [r"jenkins", r"x-jenkins"],
    "GitLab": [r"\bgitlab\b"],
    "Drupal": [r"\bdrupal\b"],
    "Joomla": [r"\bjoomla\b"],
    "Grafana": [r"\bgrafana\b"],
    "Kibana": [r"\bkibana\b"],
    "phpMyAdmin": [r"phpmyadmin"],
    "Jira": [r"atlassian jira", r"\bjira\b"],
    "Confluence": [r"atlassian confluence", r"\bconfluence\b"],
    "Nginx": [r"\bnginx\b"],
    "Apache": [r"\bapache\b"],
    "IIS": [r"\bmicrosoft-iis\b", r"\biis\b"],
    "ASP.NET": [r"asp\.net", r"x-aspnet-version"],
}


def fingerprint_http_response(response):
    """Return a list of likely web technologies/services from headers/body."""
    blob = " ".join([
        response.headers.get("Server", ""),
        response.headers.get("X-Powered-By", ""),
        response.headers.get("X-Generator", ""),
        response.headers.get("Set-Cookie", ""),
        response.text[:12000] if response.text else "",
    ]).lower()

    hits = []
    for name, patterns in WEB_FINGERPRINT_PATTERNS.items():
        if any(re.search(pattern, blob, re.I) for pattern in patterns):
            hits.append(name)

    # Cookie-specific fingerprints.
    cookies = response.headers.get("Set-Cookie", "").lower()
    if "jsessionid" in cookies and "Tomcat" not in hits:
        hits.append("Java/JSP (JSESSIONID)")
    if "phpsessid" in cookies and "PHP" not in hits:
        hits.append("PHP (PHPSESSID)")
    if "asp.net_sessionid" in cookies and "ASP.NET" not in hits:
        hits.append("ASP.NET")

    return hits


def get_endpoint_wordlist():
    """Use a common local wordlist if available; otherwise use built-ins."""
    candidates = [
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/dirbuster/wordlists/directory-list-2.3-small.txt",
    ]
    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate

    return None


def fuzz_http_endpoints(host, nmap_result):
    """Probe common endpoints on every discovered HTTP(S) service."""
    if requests is None:
        bad("The `requests` library is required for HTTP endpoint scanning.")
        return

    web_ports = get_web_ports(nmap_result)
    if not web_ports:
        return

    section("HTTP Endpoint & Technology Enumeration")

    local_wordlist = get_endpoint_wordlist()
    if local_wordlist:
        try:
            with open(local_wordlist, "r", errors="ignore") as f:
                endpoints = [
                    line.strip().lstrip("/")
                    for line in f
                    if line.strip() and not line.startswith("#")
                ]
        except OSError:
            endpoints = DEFAULT_ENDPOINTS
    else:
        endpoints = DEFAULT_ENDPOINTS
        info("No common system web wordlist found; using SmartScan built-in endpoint list.")

    # Keep requests bounded even if a very large wordlist is installed.
    endpoints = endpoints[:5000]

    for port, is_ssl in web_ports:
        scheme = "https" if is_ssl else "http"
        base_url = f"{scheme}://{host}:{port}/"

        try:
            root = requests.get(
                base_url, timeout=6, verify=False, allow_redirects=False
            )
        except requests.RequestException as exc:
            warn(f"{base_url} -> connection failed ({exc})")
            continue

        root_hits = fingerprint_http_response(root)
        server = root.headers.get("Server", "")
        powered = root.headers.get("X-Powered-By", "")

        print(f"\n{base_url}")
        print(f"  Server: {server or 'unknown'}")
        if powered:
            print(f"  X-Powered-By: {powered}")
        if root_hits:
            good(f"  Possible technology/service: {', '.join(dict.fromkeys(root_hits))}")

        found = []

        def probe(endpoint):
            url = f"{base_url}{endpoint}"
            try:
                response = requests.get(
                    url, timeout=5, verify=False, allow_redirects=False
                )
                # Ignore the usual not-found responses, but retain redirects,
                # authentication pages, and any successful response.
                if response.status_code not in (404, 400):
                    return (
                        endpoint,
                        response.status_code,
                        len(response.content),
                        response.headers.get("Location", ""),
                        fingerprint_http_response(response),
                    )
            except requests.RequestException:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
            for result in pool.map(probe, endpoints):
                if result:
                    found.append(result)

        if found:
            good("Potential Endpoints Discovered!")
            for endpoint, status, length, location, technologies in found:
                extra = []
                if location:
                    extra.append(f"redirect={location}")
                if technologies:
                    extra.append(f"tech={','.join(dict.fromkeys(technologies))}")
                suffix = f"  [{' ; '.join(extra)}]" if extra else ""
                print(f"  /{endpoint} [{status}] ({length} bytes){suffix}")
        else:
            warn("No interesting endpoints discovered.")


# --------------------------------------------------------------------------- #
# VHost fuzzing
# --------------------------------------------------------------------------- #

def _random_subdomain(n=12):
    return "".join(random.choices(string.ascii_lowercase, k=n))


def get_web_ports(nmap_result):
    web = []
    for p in nmap_result.ports:
        if p["service"] == "http":
            web.append((p["port"], p["tunnel"] == "ssl"))
    return web


# Loose but safe filter for words that could plausibly be a DNS label /
# Host header value. Directory wordlists (dirbuster/seclists) are full of
# entries like "-", "%20", "*checkout*", ".htaccess" that make almost every
# web server return an immediate 400 due to malformed syntax — not because
# they're a real vhost. Testing them just wastes requests and produces
# guaranteed false positives, so they're skipped before ever hitting the
# network.
_VALID_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def _is_valid_vhost_label(word):
    return bool(_VALID_LABEL_RE.match(word))


VHOST_FUZZ_TIME = 4 * 60  # 4 minutes; intentionally bounded default.


def fuzz_vhosts(host, hostname, wordlist_path, nmap_result, time_limit=VHOST_FUZZ_TIME):
    if requests is None:
        bad("The `requests` library is required for vhost fuzzing (pip install requests).")
        return

    if not os.path.isfile(wordlist_path):
        bad(f"Wordlist not found: {wordlist_path}")
        return

    web_ports = get_web_ports(nmap_result)
    if not web_ports:
        warn("No HTTP(S) services discovered by nmap to run vhost fuzzing against.")
        return

    try:
        # Kept open for the lifetime of the fuzz (not a `with` block) since
        # `words` is a lazy generator consumed across the whole function.
        # Do not build a gigantic list and submit the entire wordlist.
        # VHost fuzzing is deliberately time-bounded.
        wordlist_file = open(wordlist_path, "r", errors="ignore")
        words = (
            w.strip()
            for w in wordlist_file
            if w.strip()
            and not w.startswith("#")
            and _is_valid_vhost_label(w.strip())
        )
    except OSError as exc:
        bad(f"Could not read wordlist: {exc}")
        return

    print(f"wordlist: {wordlist_path}")
    print(f"Hostname: *.{hostname}")
    print(bold(f"Time limit: {time_limit // 60}m {time_limit % 60}s"))
    info("Fuzzing for vhosts...")

    deadline = time.monotonic() + time_limit
    total_tested = 0

    try:
        for port, is_ssl in web_ports:
            if time.monotonic() >= deadline:
                warn("VHost fuzzing time limit reached — stopping.")
                return

            scheme = "https" if is_ssl else "http"
            base_url = f"{scheme}://{host}:{port}/"

            # Establish a baseline using a random hostname that should not exist.
            baseline_host_header = f"{_random_subdomain()}.{hostname}"

            try:
                baseline = requests.get(
                    base_url,
                    headers={"Host": baseline_host_header},
                    timeout=5,
                    verify=False,
                    allow_redirects=False,
                )
                baseline_len = len(baseline.content)
                baseline_status = baseline.status_code
            except requests.RequestException as exc:
                warn(
                    f"Could not reach {base_url} to establish a baseline "
                    f"({exc}); skipping this port."
                )
                continue

            info(f"Fuzzing vhosts on port {port} ({scheme})...")

            # Every successful response is kept (not just ones that differ
            # from the baseline) so a majority/"noise" signature can be
            # computed afterwards — the same idea as running plain ffuf
            # first, eyeballing the common response size, then re-running
            # with `-fs/-fw <size>` to filter it out. Here it's automatic.
            all_responses = []

            def probe(word):
                vhost = f"{word}.{hostname}"
                try:
                    r = requests.get(
                        base_url,
                        headers={"Host": vhost},
                        timeout=3,
                        verify=False,
                        allow_redirects=False,
                    )
                    return (vhost, r.status_code, len(r.content))
                except requests.RequestException:
                    return None

            # Process the wordlist in bounded batches. This prevents a million-
            # entry wordlist from creating a million queued futures.
            while time.monotonic() < deadline:
                batch = []

                try:
                    for _ in range(40):
                        if time.monotonic() >= deadline:
                            break
                        batch.append(next(words))
                except StopIteration:
                    pass

                if not batch:
                    break

                pool = concurrent.futures.ThreadPoolExecutor(max_workers=20)
                futures = [pool.submit(probe, word) for word in batch]

                remaining = max(0, deadline - time.monotonic())

                try:
                    for future in concurrent.futures.as_completed(
                        futures,
                        timeout=remaining,
                    ):
                        result = future.result()
                        if result:
                            all_responses.append(result)

                        if time.monotonic() >= deadline:
                            break
                except concurrent.futures.TimeoutError:
                    pass
                finally:
                    # Do not wait for unfinished HTTP requests after the global
                    # deadline. They have short per-request timeouts anyway.
                    for future in futures:
                        future.cancel()
                    pool.shutdown(wait=False, cancel_futures=True)

                total_tested += len(batch)
                remaining_s = max(0, deadline - time.monotonic())
                sys.stdout.write(
                    f"\r{Fore.BLUE}[*]{Style.RESET_ALL} "
                    f"{bold(f'{remaining_s:0.0f}s remaining')} | "
                    f"tested {total_tested} words | "
                    f"{len(all_responses)} responses so far"
                )
                sys.stdout.flush()

                if time.monotonic() >= deadline:
                    _clear_line()
                    warn("VHost fuzzing time limit reached — stopping.")
                    break

            _clear_line()

            # Auto-filter noise: the random baseline signature, plus the
            # single most common (status, length) signature seen across all
            # responses on this port — the same effect as ffuf's -fs/-fw,
            # but computed automatically instead of by eyeballing a first pass.
            real_hits = []
            if all_responses:
                sig_counts = collections.Counter(
                    (status, length) for _, status, length in all_responses
                )
                noise_sigs = {(baseline_status, baseline_len)}
                most_common_sig, most_common_count = sig_counts.most_common(1)[0]
                noise_sigs.add(most_common_sig)

                real_hits = [
                    (vhost, status, length)
                    for vhost, status, length in all_responses
                    if (status, length) not in noise_sigs
                ]

                if most_common_count > 1:
                    info(
                        f"Auto-filtered {most_common_count} responses matching "
                        f"the common baseline signature "
                        f"[{most_common_sig[0]}] ({most_common_sig[1]} bytes) "
                        f"— equivalent to ffuf's -fs/-fw."
                    )

            if real_hits:
                good("Potential Vhosts Discovered!")
                for vhost, status, length in real_hits:
                    print(f"  {vhost} [{status}] ({length} bytes)")
            else:
                warn(f"No potential vhosts discovered on port {port}.")

        if time.monotonic() >= deadline:
            warn(
                f"VHost fuzzing finished because the {time_limit // 60}-minute "
                "time limit was reached."
            )
        else:
            info("VHost wordlist exhausted before the time limit.")
    finally:
        wordlist_file.close()


# --------------------------------------------------------------------------- #
# Argument parsing / CLI
# --------------------------------------------------------------------------- #

USAGE = """SmartScan.py -H <target_ip> <options>

Options:
  -H <target_ip>          Target host to scan (required)
  -vhost <hostname>       Base hostname to use for vhost scanning
  -vhost-list <path>      Wordlist for vhost scanning
                           e.g. /usr/share/dirbuster/wordlists/dirbuster.txt
  -vhost-time <seconds>    Maximum vhost fuzzing time (default: 240)
                           Fuzzing stops after this long even if the
                           wordlist isn't exhausted.
  -p <ports>               Restrict nmap to specific ports/ranges (optional)
  -h, --help               Show this help message and exit

If neither -vhost nor any other option is given, SmartScan simply runs
a smart recon scan: nmap -> OS guess -> open ports -> null/anon session
checks on common services.
"""


def build_parser():
    parser = argparse.ArgumentParser(
        prog="SmartScan.py",
        add_help=False,
        usage=argparse.SUPPRESS,
    )
    parser.add_argument("-H", dest="target", metavar="<target_ip>")
    parser.add_argument("-vhost", dest="vhost", metavar="<hostname>")
    parser.add_argument("-vhost-list", dest="vhost_list", metavar="<path>")
    parser.add_argument(
        "-vhost-time",
        dest="vhost_time",
        metavar="<seconds>",
        type=int,
        default=VHOST_FUZZ_TIME,
    )
    parser.add_argument("-p", dest="ports", metavar="<ports>")
    parser.add_argument("-h", "--help", dest="help", action="store_true")
    return parser


def print_help():
    print(USAGE)


def main():
    print_banner()

    parser = build_parser()
    args = parser.parse_args()

    if args.help or len(sys.argv) == 1:
        print_help()
        sys.exit(0)

    if not args.target:
        bad("Missing required option -H <target_ip>")
        print_help()
        sys.exit(1)

    if args.vhost and not args.vhost_list:
        bad("-vhost was given but -vhost-list <path> is required alongside it.")
        sys.exit(1)

    if args.vhost_time <= 0:
        bad("-vhost-time must be a positive number of seconds.")
        sys.exit(1)

    target = args.target

    # -------- nmap / cached nmap --------
    # A cached report is intentionally used only for the default nmap filename.
    # If -p is supplied, run a fresh scan because the requested port scope may
    # differ from the cached report.
    nmap_result = None
    if args.ports is None:
        nmap_result = cached_nmap_result(target)

    if nmap_result is None:
        nmap_result = run_nmap(target, ports=args.ports)

    section("Open Ports Discovered")
    if not nmap_result.ports:
        warn("No open ports found (host may be filtered/down, or you may need -Pn tuning).")
    for p in sorted(nmap_result.ports, key=lambda x: x["port"]):
        line = format_service_line(p)

        # try a friendlier web fingerprint on top of nmap's guess
        if p["service"] == "http":
            fp = fingerprint_web_service(target, p["port"], p["tunnel"] == "ssl")
            if fp:
                line += f" -> possible {fp}"
        print(line)

    # -------- DNS --------
    if any(p["port"] == 53 and p["proto"] in ("tcp", "udp") for p in nmap_result.ports):
        enumerate_dns(target, args.vhost, nmap_result)

    # -------- HTTP endpoint + technology enumeration --------
    fuzz_http_endpoints(target, nmap_result)

    # -------- OS guess --------
    os_name, os_reason = guess_os(nmap_result)
    section(f"Host seems to be - {os_name}")
    info(f"(based on {os_reason})")

    # -------- null/anon session checks --------
    run_null_session_checks(target, nmap_result)

    # -------- vhost fuzzing (optional) --------
    if args.vhost:
        section("VHost Scanning")
        fuzz_vhosts(
            target, args.vhost, args.vhost_list, nmap_result,
            time_limit=args.vhost_time,
        )

    print()
    good(f"Done. Raw nmap output saved to {nmap_result.raw_txt_path}.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        bad("Interrupted by user.")
        sys.exit(130)
