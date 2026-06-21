"""
Generate a rich synthetic network_log.csv with 10 distinct attacker IPs
using varied attack patterns — designed for the Network Bouncer hackathon demo.

Attackers
---------
1.  192.168.1.10  — Vertical Port Scan (25 ports on 1 host)
2.  172.16.0.50   — Horizontal Port Scan (SSH sweep across 35 hosts)
3.  10.10.10.200  — Strobe Scan (13 hosts × 12 ports)
4.  10.20.30.100  — High-Rate Vertical Scan (30 ports, fast)
5.  192.168.5.77  — Slow Stealth Scan (spread over a long window)
6.  10.0.99.1     — Distributed Scan Campaign (part of coordinated subnet probe)
7.  10.0.99.2     — Distributed Scan Campaign (same campaign, different src IP)
8.  10.0.99.3     — Distributed Scan Campaign (same campaign, different src IP)
9.  172.31.200.5  — Backdoor / C2 Beacon pattern (many repeated connections)
10. 10.50.0.8     — Aggressive Horizontal + Vertical Combo (SYN flood style)

Normal traffic from: 192.168.10.5, 10.1.1.20, 10.2.2.30
"""
import csv
import random

random.seed(42)

HEADER = [
    'srcip','sport','dstip','dsport','proto','state',
    'dur','sbytes','dbytes','sttl','dttl','sloss','dloss',
    'service','Sload','Dload','Spkts','Dpkts','swin','dwin',
    'stcpb','dtcpb','smeansz','dmeansz','trans_depth','res_bdy_len',
    'Sjit','Djit','Stime','Ltime','Sintpkt','Dintpkt',
    'tcprtt','synack','ackdat','is_sm_ips_ports','ct_state_ttl',
    'ct_flw_http_mthd','is_ftp_login','ct_ftp_cmd',
    'ct_srv_src','ct_srv_dst','ct_dst_ltm','ct_src_ltm',
    'ct_src_dport_ltm','ct_dst_sport_ltm','ct_dst_src_ltm',
    'attack_cat','Label'
]

rows = []
BASE_TIME = 1700000000.0


def make_row(srcip, sport, dstip, dsport, proto, state, stime,
             dur=0.001, sbytes=60, attack_cat='', label=0, service='-'):
    ltime = stime + dur
    loss = 1 if state in ('REQ', 'INT', 'RST') else 0
    return [
        srcip, sport, dstip, dsport, proto, state,
        dur, sbytes, 0, 64, 0, loss, 0,
        service,
        48000, 0, 1, 0, 0, 0, 0, 0, 60, 0, 0, 0, 0, 0,
        round(stime, 3), round(ltime, 3),
        0.001, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1,
        attack_cat, label
    ]


# ─────────────────────────────────────────────────────────────────────────────
# ATTACKER 1: Vertical Port Scan — 192.168.1.10
# Scans 25 unique ports on one host (10.0.0.1) in <60 seconds
# ─────────────────────────────────────────────────────────────────────────────
A1 = '192.168.1.10'
PORTS_V = [21,22,23,25,53,80,110,111,143,443,445,1433,3306,3389,
           5432,5900,6379,7001,8080,8443,9200,27017,6667,4444,8888]
t = BASE_TIME
for i, p in enumerate(PORTS_V):
    for _ in range(6):  # 150 total conns
        svc = 'ssh' if p == 22 else 'http' if p == 80 else '-'
        rows.append(make_row(A1, 50000 + i, '10.0.0.1', p, 'tcp', 'REQ', t,
                             attack_cat='Reconnaissance', label=1, service=svc))
        t += 0.35

# ─────────────────────────────────────────────────────────────────────────────
# ATTACKER 2: Horizontal Port Scan — 172.16.0.50
# Sweeps port 22 (SSH) across 35 unique destination IPs in <60 seconds
# ─────────────────────────────────────────────────────────────────────────────
A2 = '172.16.0.50'
t = BASE_TIME
for i in range(35):
    for _ in range(2):
        rows.append(make_row(A2, 60000 + i, f'10.0.0.{i+1}', 22, 'tcp', 'INT', t,
                             attack_cat='Reconnaissance', label=1, service='ssh'))
        t += 0.8

# ─────────────────────────────────────────────────────────────────────────────
# ATTACKER 3: Strobe Scan — 10.10.10.200
# 13 hosts × 12 ports within a single 60s window
# ─────────────────────────────────────────────────────────────────────────────
A3 = '10.10.10.200'
STROBE_HOSTS = [f'192.168.1.{i}' for i in range(1, 14)]
STROBE_PORTS = [80, 443, 22, 23, 8080, 8443, 3389, 5900, 1433, 3306, 21, 25]
t = BASE_TIME
for h in STROBE_HOSTS:
    for p in STROBE_PORTS:
        svc = 'http' if p == 80 else 'ssh' if p == 22 else '-'
        rows.append(make_row(A3, 40000, h, p, 'tcp', 'RST', t,
                             attack_cat='Reconnaissance', label=1, service=svc))
        t += 0.3

# ─────────────────────────────────────────────────────────────────────────────
# ATTACKER 4: High-Rate Vertical Scan — 10.20.30.100
# 30 ports on one target, very fast connection rate (>2/sec)
# ─────────────────────────────────────────────────────────────────────────────
A4 = '10.20.30.100'
PORTS_A4 = list(range(8000, 8030))   # 30 unique ports
t = BASE_TIME + 100
for i, p in enumerate(PORTS_A4):
    for _ in range(5):  # 150 total
        rows.append(make_row(A4, 55000 + i, '10.0.5.1', p, 'tcp', 'RST', t,
                             attack_cat='Backdoor', label=1))
        t += 0.1

# ─────────────────────────────────────────────────────────────────────────────
# ATTACKER 5: Slow Stealth Scan — 192.168.5.77
# 22+ unique ports spread slowly over a long window (slow scan evading rate limits)
# Triggers 'High Failed Conn Ratio'
# ─────────────────────────────────────────────────────────────────────────────
A5 = '192.168.5.77'
PORTS_A5 = [20,21,22,23,25,53,80,110,443,1080,1194,3128,4444,
            5000,5900,6667,7777,8080,8443,9001,9090,9999]
t = BASE_TIME + 200
for i, p in enumerate(PORTS_A5):
    for _ in range(3):
        rows.append(make_row(A5, 45000 + i, '10.0.1.10', p, 'tcp', 'INT', t,
                             dur=0.05, attack_cat='Reconnaissance', label=1))
        t += 2.5   # slow — 0.4 conns/sec

# ─────────────────────────────────────────────────────────────────────────────
# ATTACKER 6, 7, 8: Distributed Scan Campaign — 10.0.99.1/2/3
# Three IPs coordinating against the same target subnet within 300 seconds
# Triggers Distributed Scan Campaign advanced correlation
# ─────────────────────────────────────────────────────────────────────────────
CAMPAIGN_TARGETS = [f'10.100.0.{i}' for i in range(1, 11)]
CAMPAIGN_PORTS   = [22, 80, 443, 3389, 8080]

for attk_idx, (attacker_ip, t_offset) in enumerate([('10.0.99.1', 0), ('10.0.99.2', 5), ('10.0.99.3', 10)]):
    t = BASE_TIME + 500 + t_offset
    for tgt in CAMPAIGN_TARGETS:
        for p in CAMPAIGN_PORTS:
            svc = 'ssh' if p == 22 else 'http' if p == 80 else '-'
            rows.append(make_row(attacker_ip, 62000 + attk_idx * 100,
                                 tgt, p, 'tcp', 'RST', t,
                                 attack_cat='Exploits', label=1, service=svc))
            t += 0.4

# ─────────────────────────────────────────────────────────────────────────────
# ATTACKER 9: Backdoor / C2 Beacon — 172.31.200.5
# Repeatedly connects to one C2 IP on a high port (4444) — many connections,
# low destination count, triggers High-Rate detection
# ─────────────────────────────────────────────────────────────────────────────
A9 = '172.31.200.5'
t = BASE_TIME + 800
for i in range(200):   # 200 beacon connections
    rows.append(make_row(A9, 53000, '45.33.32.156', 4444, 'tcp', 'CON', t,
                         dur=0.5, sbytes=512, attack_cat='Backdoor', label=1))
    t += 0.25

# ─────────────────────────────────────────────────────────────────────────────
# ATTACKER 10: Aggressive Combo Scan — 10.50.0.8
# Horizontal sweep of 30+ hosts AND multiple ports = strobe + horizontal combo
# ─────────────────────────────────────────────────────────────────────────────
A10 = '10.50.0.8'
COMBO_HOSTS = [f'172.20.0.{i}' for i in range(1, 32)]   # 31 hosts
COMBO_PORTS = [22, 80, 443, 8080, 3389]
t = BASE_TIME + 1200
for h in COMBO_HOSTS:
    for p in COMBO_PORTS:
        rows.append(make_row(A10, 58000, h, p, 'tcp', 'RST', t,
                             attack_cat='DoS', label=1))
        t += 0.15

# ─────────────────────────────────────────────────────────────────────────────
# ATTACKER 11: Second C2 Beacon channel — 10.88.0.15
# Targets port 443 (HTTPS) to blend in — high repeat connection count
# ─────────────────────────────────────────────────────────────────────────────
A11 = '10.88.0.15'
t = BASE_TIME + 1400
for i in range(180):
    rows.append(make_row(A11, 54000, '185.220.101.45', 443, 'tcp', 'CON', t,
                         dur=0.3, sbytes=256, attack_cat='Backdoor', label=1, service='-'))
    t += 0.3

# ─────────────────────────────────────────────────────────────────────────────
# ATTACKER 12: UDP Amplification Reflector — 10.77.5.22
# Sends many UDP packets to DNS/NTP ports on many hosts (horizontal UDP sweep)
# ─────────────────────────────────────────────────────────────────────────────
A12 = '10.77.5.22'
UDP_TARGETS = [f'10.200.0.{i}' for i in range(1, 35)]  # 34 hosts
t = BASE_TIME + 1600
for tgt in UDP_TARGETS:
    for p in [53, 123, 161]:   # DNS, NTP, SNMP — amplification ports
        rows.append(make_row(A12, 65000, tgt, p, 'udp', 'INT', t,
                             dur=0.002, sbytes=100, attack_cat='DoS', label=1))
        t += 0.5

# ─────────────────────────────────────────────────────────────────────────────
# ATTACKER 13 & 14: Second distributed campaign group — 10.55.1.1 / 10.55.1.2
# Coordinated probe against a different target subnet
# ─────────────────────────────────────────────────────────────────────────────
CAMPAIGN2_TARGETS = [f'192.168.200.{i}' for i in range(1, 12)]
CAMPAIGN2_PORTS   = [22, 3389, 445, 8080, 9090]

for attk_idx, (attacker_ip, t_offset) in enumerate([('10.55.1.1', 0), ('10.55.1.2', 8)]):
    t = BASE_TIME + 1900 + t_offset
    for tgt in CAMPAIGN2_TARGETS:
        for p in CAMPAIGN2_PORTS:
            svc = 'ssh' if p == 22 else '-'
            rows.append(make_row(attacker_ip, 63000 + attk_idx * 100,
                                 tgt, p, 'tcp', 'RST', t,
                                 attack_cat='Exploits', label=1, service=svc))
            t += 0.4

# ─────────────────────────────────────────────────────────────────────────────
# NORMAL TRAFFIC — 3 benign hosts
# ─────────────────────────────────────────────────────────────────────────────
NORMAL_IPS = ['192.168.10.5', '10.1.1.20', '10.2.2.30']
NORMAL_TARGETS = ['10.0.0.100', '10.0.0.101', '10.0.0.102', '10.0.0.103']
t = BASE_TIME + 2000
for n_ip in NORMAL_IPS:
    for i in range(60):
        tgt = random.choice(NORMAL_TARGETS)
        port = random.choice([80, 443])
        state = random.choice(['CON', 'FIN'])
        svc = 'http' if port == 80 else '-'
        rows.append(make_row(n_ip, 30000 + i, tgt, port, 'tcp', state, t,
                             dur=random.uniform(0.5, 5.0),
                             sbytes=random.randint(200, 4000),
                             service=svc))
        t += random.uniform(3.0, 12.0)

# ─────────────────────────────────────────────────────────────────────────────
# Write CSV
# ─────────────────────────────────────────────────────────────────────────────
output = r'c:\external\HACKTHON\dELL 2\python_analyzer\network_log.csv'
with open(output, 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(HEADER)
    writer.writerows(rows)

attack_rows = sum(1 for r in rows if r[-1] == 1)
normal_rows = sum(1 for r in rows if r[-1] == 0)

print(f"\n[+] Generated {len(rows):,} total rows -> {output}")
print(f"    Attack flows : {attack_rows:,}")
print(f"    Normal flows : {normal_rows:,}")
print()
print("    Attacker Summary:")
print(f"    1.  192.168.1.10   — Vertical Port Scan      (25 ports × 6 conns = 150 flows)")
print(f"    2.  172.16.0.50    — Horizontal Port Scan     (35 hosts × 2 conns =  70 flows)")
print(f"    3.  10.10.10.200   — Strobe Scan              (13 hosts × 12 ports = 156 flows)")
print(f"    4.  10.20.30.100   — High-Rate Vertical       (30 ports × 5 conns = 150 flows)")
print(f"    5.  192.168.5.77   — Slow Stealth Scan        (22 ports × 3 conns =  66 flows)")
print(f"    6.  10.0.99.1      — Distributed Campaign     (10 hosts × 5 ports =  50 flows)")
print(f"    7.  10.0.99.2      — Distributed Campaign     (10 hosts × 5 ports =  50 flows)")
print(f"    8.  10.0.99.3      — Distributed Campaign     (10 hosts × 5 ports =  50 flows)")
print(f"    9.  172.31.200.5   — Backdoor/C2 Beacon       (200 repeated beacon flows)")
print(f"    10. 10.50.0.8      — Aggressive Combo Scan    (31 hosts × 5 ports = 155 flows)")
print(f"    Normal:             192.168.10.5 / 10.1.1.20 / 10.2.2.30")
