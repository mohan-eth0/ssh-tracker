#!/usr/bin/env python3
"""
SSH Brute-Force Detector & Reporter
Reads /var/log/auth.log (Debian) or uses journalctl fallback.
Aggregates failed SSH attempts per IP and optionally blocks offenders.
Sends webhook alerts and writes a JSON/CSV report.

Run as root if you want auto-blocking (iptables).
"""

import re
import json
import csv
import argparse
import subprocess
import os
import sys
import time
from datetime import datetime
from collections import defaultdict

try:
    import yaml
except Exception:
    print("PyYAML is required. Install: pip3 install pyyaml")
    sys.exit(1)

try:
    import requests
except Exception:
    print("requests is required. Install: pip3 install requests")
    sys.exit(1)

# Regexes for auth.log lines (OpenSSH)
FAIL_REGEXES = [
    re.compile(r'Failed password for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)'),
    re.compile(r'Invalid user (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)'),
    re.compile(r'Failed password for invalid user (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)'),
]

DEFAULT_CONFIG = {
    'log_path': '/var/log/auth.log',
    'use_journalctl': False,
    'threshold': 5,
    'time_window_minutes': 60,
    'report_json': 'ssh_failed_report.json',
    'report_csv': 'ssh_failed_report.csv',
    'webhook_url': None,
    'block_with_iptables': False,
    'state_file': 'state.json',
    'block_comment': 'Blocked by ssh_bruteforce_detector',
    'dry_run': True  # default true to avoid accidental blocking
}

def load_config(path):
    with open(path) as f:
        cfg = yaml.safe_load(f)
    c = DEFAULT_CONFIG.copy()
    if cfg:
        c.update(cfg)
    return c

def read_auth_log(path):
    if not os.path.exists(path):
        return ""
    with open(path, 'r', errors='ignore') as f:
        return f.read()

def read_journalctl():
    # returns last 24h logs for sshd
    try:
        out = subprocess.check_output(['journalctl', '-u', 'sshd', '--since', '24 hours ago', '--no-pager'], stderr=subprocess.DEVNULL)
        return out.decode(errors='ignore')
    except subprocess.CalledProcessError:
        return ""

def parse_failures(log_text):
    failures = []
    for line in log_text.splitlines():
        for rx in FAIL_REGEXES:
            m = rx.search(line)
            if m:
                ts = extract_timestamp(line)
                failures.append({
                    'time': ts,
                    'ip': m.group('ip'),
                    'user': m.group('user'),
                    'raw': line.strip()
                })
                break
    return failures

def extract_timestamp(line):
    # Try to parse leading syslog timestamp "Nov 22 10:12:13"
    ts_rx = re.compile(r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<hms>\d{2}:\d{2}:\d{2})')
    m = ts_rx.match(line)
    if m:
        # no year in syslog: use current year
        s = f"{m.group('month')} {m.group('day')} {datetime.now().year} {m.group('hms')}"
        try:
            return datetime.strptime(s, '%b %d %Y %H:%M:%S').isoformat()
        except Exception:
            pass
    # fallback to now
    return datetime.now().isoformat()

def aggregate(failures, window_minutes):
    cutoff = datetime.now().timestamp() - (window_minutes * 60)
    counts = defaultdict(lambda: {'count': 0, 'users': set(), 'first_seen': None, 'last_seen': None, 'raw': []})
    for f in failures:
        try:
            t = datetime.fromisoformat(f['time']).timestamp()
        except Exception:
            t = datetime.now().timestamp()
        if t < cutoff:
            continue
        ip = f['ip']
        counts[ip]['count'] += 1
        counts[ip]['users'].add(f['user'])
        counts[ip]['raw'].append(f['raw'])
        if not counts[ip]['first_seen'] or f['time'] < counts[ip]['first_seen']:
            counts[ip]['first_seen'] = f['time']
        if not counts[ip]['last_seen'] or f['time'] > counts[ip]['last_seen']:
            counts[ip]['last_seen'] = f['time']
    # convert sets
    for ip in counts:
        counts[ip]['users'] = list(counts[ip]['users'])
    return counts

def load_state(path):
    if os.path.exists(path):
        try:
            with open(path) as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_state(path, data):
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)

def send_webhook(url, message):
    if not url:
        return
    payload = {'text': message}
    try:
        r = requests.post(url, json=payload, timeout=10)
        return r.status_code
    except Exception as e:
        print("Webhook send failed:", e)
        return None

def block_ip_iptables(ip, comment, dry_run=True):
    # This function requires root. Use with caution.
    cmd = ['iptables', '-I', 'INPUT', '-s', ip, '-j', 'DROP', '-m', 'comment', '--comment', comment]
    print("Blocking IP (iptables):", ' '.join(cmd))
    if dry_run:
        print("Dry run enabled - not executing iptables.")
        return True
    try:
        subprocess.check_call(cmd)
        return True
    except subprocess.CalledProcessError as e:
        print("Failed to add iptables rule:", e)
        return False

def write_reports(json_path, csv_path, agg):
    # JSON
    with open(json_path, 'w') as f:
        json.dump({'generated_at': datetime.now().isoformat(), 'data': agg}, f, indent=2)
    # CSV
    with open(csv_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['ip', 'count', 'users', 'first_seen', 'last_seen'])
        for ip, v in agg.items():
            writer.writerow([ip, v['count'], ';'.join(v['users']), v['first_seen'], v['last_seen']])

def main():
    parser = argparse.ArgumentParser(description="SSH Brute-force detector")
    parser.add_argument('--config', default='config.yaml')
    args = parser.parse_args()

    cfg = load_config(args.config)
    log_text = ""
    if cfg.get('use_journalctl'):
        log_text = read_journalctl()
    else:
        log_text = read_auth_log(cfg['log_path'])
        if not log_text and cfg.get('use_journalctl') is False:
            # fallback
            log_text = read_journalctl()

    failures = parse_failures(log_text)
    agg = aggregate(failures, cfg['time_window_minutes'])

    print(f"Found {len(failures)} failed login events; {len(agg)} unique offending IPs within last {cfg['time_window_minutes']} minutes.")

    # Load state and determine new offenders
    state = load_state(cfg['state_file'])
    blocked = state.get('blocked', {})
    alerted = state.get('alerted', {})

    new_alerts = []
    for ip, v in agg.items():
        cnt = v['count']
        if cnt >= cfg['threshold']:
            if ip not in alerted:
                msg = f"ALERT: {ip} had {cnt} failed SSH attempts (users: {', '.join(v['users'])}). First: {v['first_seen']}, Last: {v['last_seen']}"
                print(msg)
                new_alerts.append((ip, msg))
                alerted[ip] = {'count': cnt, 'first_seen': v['first_seen'], 'last_seen': v['last_seen'], 'time': datetime.now().isoformat()}
            # Optionally block
            if cfg.get('block_with_iptables'):
                # Avoid double-blocking
                if ip not in blocked:
                    res = block_ip_iptables(ip, cfg.get('block_comment', 'blocked-by-script'), dry_run=cfg.get('dry_run', True))
                    if res:
                        blocked[ip] = {'time': datetime.now().isoformat(), 'count': cnt}
    # Write reports
    write_reports(cfg['report_json'], cfg['report_csv'], agg)

    # Send notifications
    if cfg.get('webhook_url'):
        for ip, msg in new_alerts:
            send_webhook(cfg['webhook_url'], msg)

    # Save updated state
    state['blocked'] = blocked
    state['alerted'] = alerted
    save_state(cfg['state_file'], state)

    print("Reports saved:", cfg['report_json'], cfg['report_csv'])
    if new_alerts:
        print("New alerts sent for:", [ip for ip, _ in new_alerts])
    else:
        print("No new alerts.")

if __name__ == '__main__':
    main()
