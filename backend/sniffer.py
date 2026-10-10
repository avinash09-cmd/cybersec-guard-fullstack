"""
sniffer.py
----------
Packet Sniffer & Traffic Analyzer — Wireshark (tshark)-powered.

Primary path: shells out to `tshark` (Wireshark's command-line capture
engine — same capture core as the Wireshark GUI) to capture live packets
and extract per-packet fields, then runs the same anomaly heuristics as
before: ARP spoofing, SYN floods, port-scan behavior.

Falls back to a Scapy-based capture if tshark isn't installed.

Every capture session (summary + alerts) is persisted to the database.
"""

import json
import shutil
import subprocess
import time
from collections import Counter, defaultdict
from datetime import datetime

from database import get_session, TrafficSession, TrafficAlert

try:
    from scapy.all import sniff, IP, TCP, ARP
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False


def tshark_available():
    return shutil.which("tshark") is not None


# ---------------------------------------------------------------------------
# Shared anomaly-detection logic (used by both engines)
# ---------------------------------------------------------------------------

class TrafficAnalyzer:
    def __init__(self, syn_flood_threshold=50, port_scan_threshold=15, window_seconds=10):
        self.protocol_counts = Counter()
        self.arp_table = defaultdict(set)
        self.syn_tracker = defaultdict(list)
        self.port_tracker = defaultdict(set)
        self.syn_flood_threshold = syn_flood_threshold
        self.port_scan_threshold = port_scan_threshold
        self.window_seconds = window_seconds
        self.alerts = []
        self.packet_count = 0

    def _add_alert(self, alert_type, message):
        entry = {"type": alert_type, "message": message}
        if entry not in self.alerts:
            self.alerts.append(entry)

    def record(self, protocol, src_ip=None, dport=None, arp_op=None, arp_ip=None, arp_mac=None, is_syn=False):
        self.packet_count += 1
        self.protocol_counts[protocol] += 1

        if arp_op == 2 and arp_ip and arp_mac:
            self.arp_table[arp_ip].add(arp_mac)
            if len(self.arp_table[arp_ip]) > 1:
                self._add_alert("arp_spoof", f"IP {arp_ip} claimed by multiple MACs: {self.arp_table[arp_ip]}")

        if src_ip and dport:
            self.port_tracker[src_ip].add(dport)
            if len(self.port_tracker[src_ip]) == self.port_scan_threshold:
                self._add_alert("port_scan", f"{src_ip} touched {self.port_scan_threshold}+ distinct destination ports")

        if src_ip and is_syn:
            now = time.time()
            self.syn_tracker[src_ip].append(now)
            self.syn_tracker[src_ip] = [t for t in self.syn_tracker[src_ip] if now - t <= self.window_seconds]
            if len(self.syn_tracker[src_ip]) > self.syn_flood_threshold:
                self._add_alert("syn_flood", f"{src_ip} sent {len(self.syn_tracker[src_ip])} SYNs in {self.window_seconds}s")
                self.syn_tracker[src_ip] = []

    def summary(self):
        return dict(self.protocol_counts)


# ---------------------------------------------------------------------------
# tshark engine
# ---------------------------------------------------------------------------

def capture_with_tshark(duration=10, interface=None):
    analyzer = TrafficAnalyzer()
    fields = ["frame.protocols", "ip.src", "tcp.dstport", "tcp.flags.syn",
              "arp.opcode", "arp.src.proto_ipv4", "arp.src.hw_mac"]
    cmd = ["tshark", "-a", f"duration:{duration}", "-T", "fields"]
    for f in fields:
        cmd += ["-e", f]
    if interface:
        cmd = ["tshark", "-i", interface] + cmd[1:]

    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=duration + 30)
    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 7:
            continue
        protocols, src_ip, dport, syn_flag, arp_op, arp_ip, arp_mac = parts[:7]
        top_proto = protocols.split(":")[-1].upper() if protocols else "OTHER"
        analyzer.record(
            protocol=top_proto,
            src_ip=src_ip or None,
            dport=int(dport) if dport.isdigit() else None,
            arp_op=int(arp_op) if arp_op.isdigit() else None,
            arp_ip=arp_ip or None,
            arp_mac=arp_mac or None,
            is_syn=(syn_flag == "1"),
        )
    return analyzer


# ---------------------------------------------------------------------------
# Scapy fallback engine
# ---------------------------------------------------------------------------

def capture_with_scapy(duration=10, interface=None, max_packets=500):
    analyzer = TrafficAnalyzer()

    def handle(pkt):
        if pkt.haslayer(ARP):
            a = pkt[ARP]
            analyzer.record(protocol="ARP", arp_op=a.op, arp_ip=a.psrc, arp_mac=a.hwsrc)
            return
        if pkt.haslayer(IP):
            proto = "TCP" if pkt.haslayer(TCP) else "OTHER-IP"
            dport = pkt[TCP].dport if pkt.haslayer(TCP) else None
            is_syn = pkt.haslayer(TCP) and pkt[TCP].flags == "S"
            analyzer.record(protocol=proto, src_ip=pkt[IP].src, dport=dport, is_syn=is_syn)
        else:
            analyzer.record(protocol="NON-IP")

    sniff(iface=interface, prn=handle, timeout=duration, count=max_packets, store=False)
    return analyzer


# ---------------------------------------------------------------------------
# Public entrypoint used by the API
# ---------------------------------------------------------------------------

def capture_and_store(duration=10, interface=None):
    if tshark_available():
        engine_used = "tshark"
        analyzer = capture_with_tshark(duration, interface)
    elif SCAPY_AVAILABLE:
        engine_used = "scapy-fallback"
        analyzer = capture_with_scapy(duration, interface)
    else:
        raise RuntimeError("Neither tshark nor scapy is available on this system.")

    db = get_session()
    try:
        session = TrafficSession(
            engine=engine_used,
            packet_count=analyzer.packet_count,
            protocol_summary=json.dumps(analyzer.summary()),
            created_at=datetime.utcnow(),
        )
        db.add(session)
        db.flush()
        for a in analyzer.alerts:
            db.add(TrafficAlert(session_id=session.id, alert_type=a["type"], message=a["message"]))
        db.commit()
        session_id = session.id
    finally:
        db.close()

    return {
        "session_id": session_id,
        "engine": engine_used,
        "packet_count": analyzer.packet_count,
        "protocol_summary": analyzer.summary(),
        "alerts": analyzer.alerts,
    }
