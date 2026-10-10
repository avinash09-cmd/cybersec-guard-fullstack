"""
scanner.py
----------
Network Vulnerability Scanner — Nmap-powered.

Primary path: shells out to `nmap -sV -T4 -oX -` (XML to stdout) and parses
the result for open ports, service/version banners, and script output.
Falls back to a built-in threaded socket scan if nmap isn't installed on
the host, so the module still works in restricted environments (CI boxes,
locked-down student machines, etc).

Every scan is persisted to the database via database.py.
"""

import shutil
import socket
import subprocess
import threading
import xml.etree.ElementTree as ET
from queue import Queue
from datetime import datetime

from database import get_session, ScanResult, ScanPort

COMMON_RISKS = {
    21: ("FTP", "Often allows anonymous login; credentials sent in cleartext."),
    22: ("SSH", "Check for outdated OpenSSH versions / weak auth config."),
    23: ("Telnet", "Cleartext protocol — should not be exposed at all."),
    25: ("SMTP", "Can be abused for open relay / user enumeration."),
    53: ("DNS", "Misconfigured recursive resolvers can enable amplification attacks."),
    80: ("HTTP", "Check for outdated web server banners and missing security headers."),
    110: ("POP3", "Cleartext credentials unless wrapped in TLS."),
    135: ("MSRPC", "Historically linked to remote code execution exploits (e.g. Blaster)."),
    139: ("NetBIOS", "Legacy SMB — vulnerable to enumeration attacks."),
    143: ("IMAP", "Cleartext credentials unless wrapped in TLS."),
    443: ("HTTPS", "Verify TLS version/cipher suite; check certificate validity."),
    445: ("SMB", "History of critical RCE vulnerabilities (e.g. EternalBlue/MS17-010)."),
    3306: ("MySQL", "Should never be exposed to the public internet."),
    3389: ("RDP", "Frequent brute-force target; check for BlueKeep-class issues."),
    5432: ("PostgreSQL", "Should not be internet-facing without strict auth."),
    6379: ("Redis", "Often left unauthenticated — full data/RCE exposure risk."),
    8080: ("HTTP-alt", "Common proxy/admin panel port — check for default creds."),
}
DEFAULT_PORTS = list(COMMON_RISKS.keys()) + [20, 587, 993, 995, 8443]


def nmap_available():
    return shutil.which("nmap") is not None


def run_nmap_scan(target, ports=None):
    """Runs `nmap -sV` and returns a list of {port, service, banner, risk_note} dicts."""
    port_arg = ",".join(str(p) for p in (ports or DEFAULT_PORTS))
    cmd = ["nmap", "-sV", "-T4", "-p", port_arg, "-oX", "-", target]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    root = ET.fromstring(proc.stdout)

    results = []
    for host in root.findall("host"):
        ports_el = host.find("ports")
        if ports_el is None:
            continue
        for port_el in ports_el.findall("port"):
            state = port_el.find("state")
            if state is None or state.get("state") != "open":
                continue
            portid = int(port_el.get("portid"))
            service_el = port_el.find("service")
            service_name = service_el.get("name") if service_el is not None else "unknown"
            product = service_el.get("product", "") if service_el is not None else ""
            version = service_el.get("version", "") if service_el is not None else ""
            banner = f"{product} {version}".strip() or None
            known_service, risk_note = COMMON_RISKS.get(portid, (service_name, None))
            results.append({
                "port": portid,
                "service": known_service,
                "banner": banner,
                "risk_note": risk_note,
            })
    return results


# ---------------------------------------------------------------------------
# Fallback: pure-Python threaded TCP connect scan (no nmap required)
# ---------------------------------------------------------------------------

def grab_banner(sock):
    try:
        sock.settimeout(1)
        banner = sock.recv(1024).decode(errors="ignore").strip()
        return banner if banner else None
    except Exception:
        return None


def _scan_port(target, port, results, lock, timeout=0.75):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((target, port)) == 0:
                banner = grab_banner(s)
                service, risk = COMMON_RISKS.get(port, ("Unknown", None))
                with lock:
                    results.append({"port": port, "service": service, "banner": banner, "risk_note": risk})
    except Exception:
        pass


def run_fallback_scan(target, ports=None, max_threads=100):
    ports = ports or DEFAULT_PORTS
    results, lock, q = [], threading.Lock(), Queue()
    for p in ports:
        q.put(p)

    def worker():
        while not q.empty():
            try:
                port = q.get_nowait()
            except Exception:
                return
            _scan_port(target, port, results, lock)
            q.task_done()

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(min(max_threads, len(ports)))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    results.sort(key=lambda r: r["port"])
    return results


# ---------------------------------------------------------------------------
# Public entrypoint used by the API
# ---------------------------------------------------------------------------

def scan_and_store(target, ports=None):
    target_ip = socket.gethostbyname(target)
    engine_used = "nmap" if nmap_available() else "socket-fallback"

    if engine_used == "nmap":
        try:
            results = run_nmap_scan(target_ip, ports)
        except Exception:
            # nmap present but failed for some reason (permissions, bad args) — fall back
            engine_used = "socket-fallback"
            results = run_fallback_scan(target_ip, ports)
    else:
        results = run_fallback_scan(target_ip, ports)

    db = get_session()
    try:
        scan = ScanResult(target=target_ip, engine=engine_used, created_at=datetime.utcnow())
        db.add(scan)
        db.flush()
        for r in results:
            db.add(ScanPort(scan_id=scan.id, port=r["port"], service=r["service"],
                             banner=r["banner"], risk_note=r["risk_note"]))
        db.commit()
        scan_id = scan.id
    finally:
        db.close()

    return {"scan_id": scan_id, "target": target_ip, "engine": engine_used, "results": results}
