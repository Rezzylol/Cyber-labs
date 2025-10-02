#!/usr/bin/env python3
"""
log_parser.py

Simple parser to extract failed SSH login attempts from syslog-style files
and produce a CSV summary: timestamp, source_ip, username, raw_line
"""

import re
import csv
import sys
from pathlib import Path
from datetime import datetime

SSH_FAIL_RE = re.compile(
    r'^(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>[\w\-\._]+)\s+(?P<svc>sshd(?:\[\d+\])?:)\s+(?P<msg>.*(?:Failed password|Invalid user).*)$'
)
IP_RE = re.compile(r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})')
USER_RE = re.compile(r'for invalid user (?P<user>\S+)|for (?P<user2>\S+)\sfrom')

def parse_file(path):
    results = []
    for line in Path(path).read_text(errors='ignore').splitlines():
        m = SSH_FAIL_RE.search(line)
        if not m:
            continue
        ts_raw = m.group('ts')
        # Syslog doesn't include year — assume current year
        try:
            ts = datetime.strptime(f"{ts_raw} {datetime.now().year}", "%b %d %H:%M:%S %Y")
        except Exception:
            ts = ts_raw
        msg = m.group('msg')
        ip_m = IP_RE.search(msg)
        user_m = USER_RE.search(msg)
        ip = ip_m.group('ip') if ip_m else ''
        user = (user_m.group('user') or user_m.group('user2')) if user_m else ''
        results.append({
            'timestamp': ts.isoformat() if isinstance(ts, datetime) else str(ts),
            'source_ip': ip,
            'username': user,
            'raw': msg.strip()
        })
    return results

def write_csv(results, out_path):
    with open(out_path, 'w', newline='') as fh:
        writer = csv.DictWriter(fh, fieldnames=['timestamp','source_ip','username','raw'])
        writer.writeheader()
        for r in results:
            writer.writerow(r)

def main(argv):
    if len(argv) < 2:
        print("Usage: log_parser.py <syslog-file> [out.csv]")
        sys.exit(2)
    src = argv[1]
    out = argv[2] if len(argv) > 2 else 'ssh_failures.csv'
    results = parse_file(src)
    write_csv(results, out)
    print(f"Wrote {len(results)} entries to {out}")

if __name__ == '__main__':
    main(sys.argv)
