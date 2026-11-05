#!/usr/bin/env python3
"""Generate a synthetic Zeek + Palo Alto log set of a chosen size for benchmarking.

Layout written under OUT (mirrors a typical sensor export / network share):

    OUT/zeek/YYYY-MM-DD/conn.HH:00:00-HH:59:59.log[.gz]
    OUT/zeek/YYYY-MM-DD/dns.HH:00:00-HH:59:59.log[.gz]
    OUT/paloalto/traffic_YYYY-MM-DD_HH.csv[.gz]
    OUT/scan/scan.csv                      (only with --scan)

Realism knobs that matter for the pipeline:
  * --overlap:  share of sessions seen by both Zeek and the firewall. The firewall row has the
                same 5-tuple but a timestamp truncated to the second and its own byte counts,
                which is what a real Zeek + PAN-OS deployment produces.
  * --dup:      share of rows written twice (overlapping log rotation / re-exported files).
  * --gz:       share of hourly files written gzip-compressed.
  * --dns:      share of Zeek bytes that go to dns.log instead of conn.log.

Size is the target *uncompressed* volume. A JSON manifest with the true counts is written to
OUT/.manifest.json (hidden, so the tool skips it) so the benchmark can compare what the tool reports with what was generated.

Deterministic for a given --seed. Uses all cores (one worker per hourly file).
"""
from __future__ import annotations

import argparse
import gzip
import json
import os
import random
import time
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime, timezone

ZEEK_CONN_HEADER = (
    "#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tconn\n"
    "#open\t{open}\n"
    "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\t"
    "orig_bytes\tresp_bytes\tconn_state\tmissed_bytes\thistory\torig_pkts\tresp_pkts\n"
    "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\t"
    "count\tstring\tcount\tcount\n")
ZEEK_DNS_HEADER = (
    "#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tdns\n"
    "#open\t{open}\n"
    "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\ttrans_id\tquery\tqtype_name\t"
    "rcode_name\tanswers\n"
    "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tcount\tstring\tstring\tstring\tvector[string]\n")
PA_HEADER = ("Receive Time,Serial #,Type,Threat/Content Type,Source address,Destination address,Rule,"
             "Application,Source Zone,Destination Zone,Source Port,Destination Port,IP Protocol,Action,"
             "Bytes,Bytes Sent,Bytes Received,Start Time,Threat/Content Name,Severity\n")

SERVICES = [  # (port, proto, zeek service, PA app, weight)
    (443, "tcp", "ssl", "ssl", 40), (80, "tcp", "http", "web-browsing", 12), (53, "udp", "dns", "dns", 18),
    (445, "tcp", "smb", "ms-ds-smb", 6), (389, "tcp", "ldap", "ldap", 4), (88, "tcp", "krb", "kerberos", 4),
    (3389, "tcp", "-", "ms-rdp", 2), (22, "tcp", "ssh", "ssh", 3), (123, "udp", "ntp", "ntp", 3),
    (1433, "tcp", "-", "mssql-db", 2), (8080, "tcp", "http", "web-browsing", 3), (502, "tcp", "modbus", "modbus", 1),
    (5985, "tcp", "-", "winrm", 1), (25, "tcp", "smtp", "smtp", 1),
]
SVC_WEIGHTS = [s[4] for s in SERVICES]
STATES = [("SF", 70), ("S0", 10), ("REJ", 8), ("RSTO", 5), ("S1", 3), ("SH", 2), ("OTH", 2)]
THREATS = ["Microsoft Windows SMB Remote Code Execution Vulnerability(91234)",
           "Apache Log4j Remote Code Execution Vulnerability(91991)",
           "HTTP Directory Traversal Vulnerability(30844)", "SSH Brute Force Attempt(40015)",
           "Suspicious DNS Query (generic:c2.example)(85001)"]
DOMAINS = ["update.example.com", "cdn.example.net", "login.example.org", "files.example.io",
           "telemetry.example.com", "mail.example.com", "api.example.net", "time.example.org"]


def _ip_int(n: int) -> str:
    return f"{n >> 24 & 255}.{n >> 16 & 255}.{n >> 8 & 255}.{n & 255}"


class World:
    """Host population shared by every worker (rebuilt from the seed in each process)."""

    def __init__(self, seed: int, hosts: int, externals: int):
        rnd = random.Random(seed)
        base = 10 << 24 | 10 << 16                                  # 10.10.0.0/16
        self.internal = [_ip_int(base + 256 + i) for i in range(hosts)]
        self.servers = self.internal[: max(20, hosts // 20)]        # 5% of hosts are servers
        self.external = []
        while len(self.external) < externals:
            a = rnd.randint(11, 223)
            if a in (10, 100, 127, 169, 172, 192):
                continue
            self.external.append(f"{a}.{rnd.randint(0, 255)}.{rnd.randint(0, 255)}.{rnd.randint(1, 254)}")
        self.dns_servers = self.servers[:2]


def _session(rnd: random.Random, w: World, ts: float):
    svc = rnd.choices(SERVICES, SVC_WEIGHTS)[0]
    port, proto = svc[0], svc[1]
    r = rnd.random()
    if r < 0.55:                                   # internal client -> internet
        src, dst = rnd.choice(w.internal), rnd.choice(w.external)
        zones = ("trust", "untrust")
    elif r < 0.85:                                 # internal client -> internal server
        src, dst = rnd.choice(w.internal), rnd.choice(w.servers)
        zones = ("trust", "dmz")
    else:                                          # internet -> exposed server
        src, dst = rnd.choice(w.external), rnd.choice(w.servers[:10])
        zones = ("untrust", "dmz")
        port, proto = (443, "tcp") if rnd.random() < 0.8 else (22, "tcp")
    if port == 53:
        dst = rnd.choice(w.dns_servers) if rnd.random() < 0.8 else dst
    state = rnd.choices([s for s, _ in STATES], [x for _, x in STATES])[0]
    ob = int(rnd.expovariate(1 / 1500)) if state not in ("S0", "REJ") else 0
    rb = int(rnd.expovariate(1 / 20000)) if state in ("SF", "RSTO", "S1") else 0
    return dict(ts=ts, src=src, sport=rnd.randint(1024, 65535), dst=dst, dport=port, proto=proto,
                zsvc=svc[2], app=svc[3], zones=zones, state=state, ob=ob, rb=rb,
                dur=round(rnd.expovariate(1 / 8), 6))


def _zeek_conn(s, uid):
    return (f"{s['ts']:.6f}\tC{uid:017x}\t{s['src']}\t{s['sport']}\t{s['dst']}\t{s['dport']}\t{s['proto']}\t"
            f"{s['zsvc']}\t{s['dur']}\t{s['ob']}\t{s['rb']}\t{s['state']}\t0\tShADadFf\t"
            f"{1 + s['ob'] // 1200}\t{1 + s['rb'] // 1200}\n")


def _pa_traffic(s):
    t = datetime.fromtimestamp(int(s["ts"]), tz=timezone.utc).strftime("%Y/%m/%d %H:%M:%S")
    action = "deny" if s["state"] == "REJ" else "allow"
    # the firewall counts headers too, so its byte counts never match Zeek's exactly
    bs, br = s["ob"] + 66, s["rb"] + (66 if s["rb"] else 0)
    return (f"{t},016401000001,TRAFFIC,end,{s['src']},{s['dst']},rule-{s['dport']},{s['app']},"
            f"{s['zones'][0]},{s['zones'][1]},{s['sport']},{s['dport']},{s['proto']},{action},"
            f"{bs + br},{bs},{br},{t},,\n")


def _pa_threat(rnd, s):
    t = datetime.fromtimestamp(int(s["ts"]), tz=timezone.utc).strftime("%Y/%m/%d %H:%M:%S")
    action = "reset-both" if rnd.random() < 0.6 else "alert"
    return (f"{t},016401000001,THREAT,vulnerability,{s['src']},{s['dst']},rule-{s['dport']},{s['app']},"
            f"{s['zones'][0]},{s['zones'][1]},{s['sport']},{s['dport']},{s['proto']},{action},"
            f",,,{t},{rnd.choice(THREATS)},{rnd.choice(['high', 'critical', 'medium'])}\n")


def _dns(rnd, w, ts, uid):
    q = rnd.choice(DOMAINS) if rnd.random() < 0.7 else f"h{rnd.randint(0, 99999)}.{rnd.choice(DOMAINS)}"
    ans = ",".join(f"{rnd.randint(11, 223)}.{rnd.randint(0, 255)}.{rnd.randint(0, 255)}.{rnd.randint(1, 254)}"
                   for _ in range(rnd.randint(1, 3)))
    return (f"{ts:.6f}\tD{uid:017x}\t{rnd.choice(w.internal)}\t{rnd.randint(1024, 65535)}\t"
            f"{rnd.choice(w.dns_servers)}\t53\tudp\t{rnd.randint(0, 65535)}\t{q}\tA\tNOERROR\t{ans}\n")


def _open(path, gz):
    return gzip.open(path + ".gz", "wt", compresslevel=3, newline="") if gz else open(path, "w", newline="")


def work(job):
    """Write one hour of logs. Returns counts for the manifest."""
    (out, seed, hosts, externals, hour_start, conn_bytes, dns_bytes, overlap, dup, gz_rate, threat_rate,
     hour_index) = job
    w = World(seed, hosts, externals)
    rnd = random.Random(seed * 1_000_003 + hour_index)
    day = datetime.fromtimestamp(hour_start, tz=timezone.utc)
    dname, hh = day.strftime("%Y-%m-%d"), day.strftime("%H")
    zdir = os.path.join(out, "zeek", dname)
    pdir = os.path.join(out, "paloalto")
    os.makedirs(zdir, exist_ok=True)
    os.makedirs(pdir, exist_ok=True)
    gz_z, gz_p, gz_d = (rnd.random() < gz_rate for _ in range(3))
    open_s = day.strftime("%Y-%m-%d-%H-%M-%S")
    zf = _open(os.path.join(zdir, f"conn.{hh}:00:00-{hh}:59:59.log"), gz_z)
    pf = _open(os.path.join(pdir, f"traffic_{dname}_{hh}.csv"), gz_p)
    zf.write(ZEEK_CONN_HEADER.format(open=open_s))
    pf.write(PA_HEADER)
    c = dict(sessions=0, zeek_conn_rows=0, pa_traffic_rows=0, pa_threat_rows=0, both_sensors=0,
             zeek_only=0, pa_only=0, exact_dup_rows_zeek=0, exact_dup_rows_pa=0, dns_rows=0,
             bytes_uncompressed=len(ZEEK_CONN_HEADER) + len(PA_HEADER),
             gz_files=int(gz_z) + int(gz_p), files=2,
             pa_rows_in_gz=0, zeek_conn_rows_in_gz=0)
    written, uid = 0, hour_index << 36
    n_est = max(1, conn_bytes // 150)
    step = 3600.0 / n_est
    ts = float(hour_start)
    while written < conn_bytes:
        ts += rnd.expovariate(1 / step)
        if ts >= hour_start + 3600:
            ts = hour_start + 3599.999
        s = _session(rnd, w, ts)
        c["sessions"] += 1
        r = rnd.random()
        # 85% of sessions cross a Zeek tap; `overlap` share of all sessions also cross the firewall
        in_zeek = r < 0.85
        in_pa = (not in_zeek) or rnd.random() < overlap / 0.85
        if in_zeek:
            line = _zeek_conn(s, uid)
            uid += 1
            reps = 2 if rnd.random() < dup else 1
            for _ in range(reps):
                zf.write(line)
            written += len(line) * reps
            c["zeek_conn_rows"] += reps
            c["exact_dup_rows_zeek"] += reps - 1
            if gz_z:
                c["zeek_conn_rows_in_gz"] += reps
        if in_pa:
            line = _pa_traffic(s)
            reps = 2 if rnd.random() < dup else 1
            for _ in range(reps):
                pf.write(line)
            written += len(line) * reps
            c["pa_traffic_rows"] += reps
            c["exact_dup_rows_pa"] += reps - 1
            if gz_p:
                c["pa_rows_in_gz"] += reps
            if s["zones"][0] == "untrust" and rnd.random() < threat_rate:
                t = _pa_threat(rnd, s)
                pf.write(t)
                written += len(t)
                c["pa_threat_rows"] += 1
        c["both_sensors"] += in_zeek and in_pa
        c["zeek_only"] += in_zeek and not in_pa
        c["pa_only"] += in_pa and not in_zeek
    c["bytes_uncompressed"] += written
    zf.close()
    pf.close()
    if dns_bytes:
        df = _open(os.path.join(zdir, f"dns.{hh}:00:00-{hh}:59:59.log"), gz_d)
        df.write(ZEEK_DNS_HEADER.format(open=open_s))
        c["files"] += 1
        c["gz_files"] += int(gz_d)
        dwritten, ts = 0, float(hour_start)
        dstep = 3600.0 / max(1, dns_bytes // 140)
        while dwritten < dns_bytes:
            ts = min(ts + rnd.expovariate(1 / dstep), hour_start + 3599.999)
            line = _dns(rnd, w, ts, uid)
            uid += 1
            df.write(line)
            dwritten += len(line)
            c["dns_rows"] += 1
        df.close()
        c["bytes_uncompressed"] += dwritten + len(ZEEK_DNS_HEADER)
    return c


def write_scan(out: str, w: World, rnd: random.Random) -> int:
    os.makedirs(os.path.join(out, "scan"), exist_ok=True)
    rows = 0
    with open(os.path.join(out, "scan", "scan.csv"), "w", newline="") as fh:
        fh.write("Plugin ID,CVE,CVSS v3.0 Base Score,Risk,Host,Protocol,Port,Name,Synopsis,Solution\n")
        for i, host in enumerate(w.internal):
            for _ in range(rnd.randint(1, 6)):
                port, proto = rnd.choice([(443, "tcp"), (445, "tcp"), (22, "tcp"), (3389, "tcp"), (0, "tcp")])
                risk, cvss = rnd.choice([("Critical", 9.8), ("High", 7.5), ("Medium", 5.3), ("Low", 3.1)])
                pid = rnd.randint(10000, 10200)
                fh.write(f"{pid},CVE-2026-{pid},{cvss},{risk},{host},{proto},{port},Synthetic finding {pid},"
                         f"Synthetic,Patch\n")
                rows += 1
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("out")
    ap.add_argument("--size", default="1G", help="target uncompressed size, e.g. 500M, 1G, 10G")
    ap.add_argument("--hours", type=int, default=0, help="hourly files to spread over (default: ~40 MB/hour)")
    ap.add_argument("--hosts", type=int, default=2000, help="internal hosts")
    ap.add_argument("--externals", type=int, default=50000, help="distinct internet addresses")
    ap.add_argument("--overlap", type=float, default=0.6, help="share of sessions seen by Zeek and the firewall")
    ap.add_argument("--dup", type=float, default=0.02, help="share of rows written twice")
    ap.add_argument("--gz", type=float, default=0.3, help="share of files gzip-compressed")
    ap.add_argument("--dns", type=float, default=0.15, help="share of bytes in Zeek dns.log")
    ap.add_argument("--threat-rate", type=float, default=0.01, help="THREAT rows per inbound firewall session")
    ap.add_argument("--scan", action="store_true", help="also write a Nessus CSV covering every internal host")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--start", default="2026-10-01T00:00:00+00:00")
    ap.add_argument("--workers", type=int, default=os.cpu_count())
    a = ap.parse_args()

    units = {"K": 1 << 10, "M": 1 << 20, "G": 1 << 30, "T": 1 << 40}
    size = int(float(a.size[:-1]) * units[a.size[-1].upper()]) if a.size[-1].upper() in units else int(a.size)
    hours = a.hours or max(1, round(size / (40 << 20)))
    per_hour = size // hours
    dns_b, conn_b = int(per_hour * a.dns), per_hour - int(per_hour * a.dns)
    start = int(datetime.fromisoformat(a.start).timestamp())
    jobs = [(a.out, a.seed, a.hosts, a.externals, start + 3600 * h, conn_b, dns_b, a.overlap, a.dup, a.gz,
             a.threat_rate, h) for h in range(hours)]
    t0 = time.time()
    total: dict[str, int] = {}
    with ProcessPoolExecutor(a.workers) as ex:
        for c in ex.map(work, jobs):
            for k, v in c.items():
                total[k] = total.get(k, 0) + v
    if a.scan:
        total["scan_rows"] = write_scan(a.out, World(a.seed, a.hosts, a.externals), random.Random(a.seed))
    on_disk = sum(os.path.getsize(os.path.join(r, f)) for r, _, fs in os.walk(a.out) for f in fs)
    manifest = {"args": vars(a), "hours": hours, "bytes_on_disk": on_disk, "seconds": round(time.time() - t0, 1),
                **total}
    with open(os.path.join(a.out, ".manifest.json"), "w") as fh:
        json.dump(manifest, fh, indent=2)
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
