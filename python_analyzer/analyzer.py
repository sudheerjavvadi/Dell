import os
import time
import pandas as pd
from collections import defaultdict, deque

class PortScanAnalyzer:
    def __init__(self, 
                 window_size=60, 
                 vertical_threshold=20, 
                 horizontal_threshold=30, 
                 strobe_ips_threshold=10, 
                 strobe_ports_threshold=10, 
                 rate_threshold=10):
        # Configuration
        self.window_size = window_size
        self.vertical_threshold = vertical_threshold
        self.horizontal_threshold = horizontal_threshold
        self.strobe_ips_threshold = strobe_ips_threshold
        self.strobe_ports_threshold = strobe_ports_threshold
        self.rate_threshold = rate_threshold
        
        # State tracking for sliding windows
        # srcip -> deque of (timestamp, dstip, dsport)
        self.connection_history = defaultdict(deque)
        
        # Cumulative stats
        # srcip -> dict of metrics
        self.ip_stats = defaultdict(lambda: {
            'total_flows': 0,
            'total_bytes': 0,
            'total_pkts': 0,
            'first_seen': float('inf'),
            'last_seen': 0,
            'unique_dst_ips': set(),
            'unique_dst_ports': set(),
            'protocols': set(),
            'states': defaultdict(int),
            'services': set(),
            'dst_ip_ports': defaultdict(set),  # dstip -> set of dsports
            
            # Slide window peak alerts
            'peak_window_dst_ips': 0,
            'peak_window_dst_ports': 0,
            'peak_window_ports_per_ip': 0,
            
            # True Labels tracking (for validation)
            'labeled_attacks': 0,
            'recon_events': 0,
            'backdoor_events': 0,
            'analysis_events': 0,
            'attack_categories': defaultdict(int)
        })

    def parse_port(self, val):
        """Resiliently parse a port value to integer."""
        if pd.isna(val):
            return -1
        val_str = str(val).strip().lower()
        if not val_str or val_str == '-':
            return -1
        if val_str.startswith('0x'):
            try:
                return int(val_str, 16)
            except ValueError:
                return -1
        try:
            return int(float(val_str))
        except ValueError:
            return -1

    def detect_headers_and_indices(self, file_path):
        """
        Inspect the first few lines of the file to determine:
        1. If it has headers.
        2. The indices or names of the key columns.
        """
        # Read the first line of the CSV
        with open(file_path, 'r', encoding='cp1252', errors='ignore') as f:
            first_line = f.readline()
        
        # Split first line
        parts = [p.strip().lower() for p in first_line.split(',')]
        
        # Key fields we need
        key_fields = ['srcip', 'sport', 'dstip', 'dsport', 'proto', 'state', 'stime', 'ltime', 'attack_cat', 'label']
        
        # Check if it has headers
        has_headers = False
        # If any of the key fields appear exactly or nearly exactly in the parts
        if any(field in parts for field in ['srcip', 'dstip', 'proto', 'sport', 'dsport']):
            has_headers = True
        
        # Standard column mapping
        col_mapping = {}
        
        if has_headers:
            # Build a lookup: lowercased_name -> original_name
            original_parts = [p.strip() for p in first_line.split(',')]
            lower_to_original = {p.lower(): orig for p, orig in zip(parts, original_parts)}
            
            for field in key_fields:
                match_orig = None
                # 1. Exact lowercase match
                if field in lower_to_original:
                    match_orig = lower_to_original[field]
                else:
                    # 2. Strip underscores match
                    for lp, orig in lower_to_original.items():
                        if field.replace('_', '') == lp.replace('_', ''):
                            match_orig = orig
                            break
                # 3. Substring fallback
                if not match_orig:
                    for lp, orig in lower_to_original.items():
                        if field in lp or lp in field:
                            match_orig = orig
                            break
                if match_orig:
                    col_mapping[field] = match_orig
            return True, col_mapping
        else:
            # Headerless - check column count
            col_count = len(parts)
            # Standard UNSW-NB15 raw data has 49 columns
            standard_cols = [
                'srcip', 'sport', 'dstip', 'dsport', 'proto', 'state', 'dur', 'sbytes', 'dbytes', 'sttl', 'dttl',
                'sloss', 'dloss', 'service', 'Sload', 'Dload', 'Spkts', 'Dpkts', 'swin', 'dwin', 'stcpb', 'dtcpb',
                'smeansz', 'dmeansz', 'trans_depth', 'res_bdy_len', 'Sjit', 'Djit', 'Stime', 'Ltime', 'Sintpkt',
                'Dintpkt', 'tcprtt', 'synack', 'ackdat', 'is_sm_ips_ports', 'ct_state_ttl', 'ct_flw_http_mthd',
                'is_ftp_login', 'ct_ftp_cmd', 'ct_srv_src', 'ct_srv_dst', 'ct_dst_ltm', 'ct_src_ltm',
                'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm', 'attack_cat', 'Label'
            ]
            
            # Map index to fields
            for idx, field in enumerate(standard_cols):
                col_mapping[field.lower()] = idx
                
            # If the column count doesn't match 49, try to guess based on values
            if col_count != 49:
                print(f"Warning: CSV has {col_count} columns (expected 49). Applying heuristic mapping.")
            
            return False, col_mapping

    def _norm_col(self, col):
        """Normalize a column name to match what pandas itertuples produces."""
        if col is None:
            return None
        import re
        # pandas replaces special chars with _ and strips leading/trailing _
        normed = re.sub(r'[^a-zA-Z0-9_]', '_', str(col))
        normed = re.sub(r'_+', '_', normed).strip('_')
        return normed

    def process_chunk(self, chunk, col_mapping, is_headered):
        """Process a chunk of the network logs dataframe."""
        # Map logical names to dataframe accessor.
        # For headered CSVs: columns are string names → normalize to valid Python identifiers.
        # For headerless CSVs: columns are integer indices → use directly (no normalization).
        def _col(name, default):
            raw = col_mapping.get(name, default if not is_headered else None)
            return self._norm_col(raw) if is_headered else raw

        srcip_col      = _col('srcip',      0)
        sport_col      = _col('sport',      1)
        dstip_col      = _col('dstip',      2)
        dsport_col     = _col('dsport',     3)
        proto_col      = _col('proto',      4)
        state_col      = _col('state',      5)
        sbytes_col     = _col('sbytes',     7)
        dbytes_col     = _col('dbytes',     8)
        spkts_col      = _col('spkts',     16)
        dpkts_col      = _col('dpkts',     17)
        service_col    = _col('service',   13)
        stime_col      = _col('stime',     28)
        ltime_col      = _col('ltime',     29)
        attack_cat_col = _col('attack_cat',47)
        label_col      = _col('label',     48)

        row_len = len(chunk.columns)
        for row in chunk.itertuples(index=False):
            try:
                if is_headered:
                    srcip      = getattr(row, srcip_col)      if srcip_col      else None
                    sport      = getattr(row, sport_col)      if sport_col      else None
                    dstip      = getattr(row, dstip_col)      if dstip_col      else None
                    dsport     = getattr(row, dsport_col)     if dsport_col     else None
                    proto      = getattr(row, proto_col)      if proto_col      else 'unknown'
                    state      = getattr(row, state_col)      if state_col      else 'unknown'
                    sbytes     = getattr(row, sbytes_col)     if sbytes_col     else 0
                    dbytes     = getattr(row, dbytes_col)     if dbytes_col     else 0
                    spkts      = getattr(row, spkts_col)      if spkts_col      else 0
                    dpkts      = getattr(row, dpkts_col)      if dpkts_col      else 0
                    service    = getattr(row, service_col)    if service_col    else '-'
                    stime      = getattr(row, stime_col)      if stime_col      else 0.0
                    ltime      = getattr(row, ltime_col)      if ltime_col      else stime
                    attack_cat = getattr(row, attack_cat_col) if attack_cat_col else None
                    label      = getattr(row, label_col)      if label_col      else 0
                else:
                    srcip      = row[srcip_col]      if srcip_col      is not None and srcip_col      < row_len else None
                    sport      = row[sport_col]      if sport_col      is not None and sport_col      < row_len else None
                    dstip      = row[dstip_col]      if dstip_col      is not None and dstip_col      < row_len else None
                    dsport     = row[dsport_col]     if dsport_col     is not None and dsport_col     < row_len else None
                    proto      = row[proto_col]      if proto_col      is not None and proto_col      < row_len else 'unknown'
                    state      = row[state_col]      if state_col      is not None and state_col      < row_len else 'unknown'
                    sbytes     = row[sbytes_col]     if sbytes_col     is not None and sbytes_col     < row_len else 0
                    dbytes     = row[dbytes_col]     if dbytes_col     is not None and dbytes_col     < row_len else 0
                    spkts      = row[spkts_col]      if spkts_col      is not None and spkts_col      < row_len else 0
                    dpkts      = row[dpkts_col]      if dpkts_col      is not None and dpkts_col      < row_len else 0
                    service    = row[service_col]    if service_col    is not None and service_col    < row_len else '-'
                    stime      = row[stime_col]      if stime_col      is not None and stime_col      < row_len else 0.0
                    ltime      = row[ltime_col]      if ltime_col      is not None and ltime_col      < row_len else stime
                    attack_cat = row[attack_cat_col] if attack_cat_col is not None and attack_cat_col < row_len else None
                    label      = row[label_col]      if label_col      is not None and label_col      < row_len else 0
            except (IndexError, AttributeError):
                continue

            if pd.isna(srcip) or pd.isna(dstip):
                continue
            srcip = str(srcip).strip()
            dstip = str(dstip).strip()
            proto = str(proto).strip().lower()
            state = str(state).strip().upper()
            service = str(service).strip().lower()
            
            sport = self.parse_port(sport)
            dsport = self.parse_port(dsport)
            try:
                sbytes = int(sbytes) if not pd.isna(sbytes) else 0
                dbytes = int(dbytes) if not pd.isna(dbytes) else 0
                spkts = int(spkts) if not pd.isna(spkts) else 0
                dpkts = int(dpkts) if not pd.isna(dpkts) else 0
                stime = float(stime)
                ltime = float(ltime)
            except ValueError:
                continue

            stats = self.ip_stats[srcip]
            stats['total_flows'] += 1
            stats['total_bytes'] += (sbytes + dbytes)
            stats['total_pkts'] += (spkts + dpkts)
            stats['first_seen'] = min(stats['first_seen'], stime)
            stats['last_seen'] = max(stats['last_seen'], ltime)
            stats['unique_dst_ips'].add(dstip)
            if dsport != -1:
                stats['unique_dst_ports'].add(dsport)
                stats['dst_ip_ports'][dstip].add(dsport)
            stats['protocols'].add(proto)
            stats['states'][state] += 1
            if service != '-':
                stats['services'].add(service)

            if label == 1 or (isinstance(label, str) and str(label).strip() == '1'):
                stats['labeled_attacks'] += 1
                if pd.notna(attack_cat):
                    cat_name = str(attack_cat).strip().lower()
                    stats['attack_categories'][cat_name] += 1
                    if 'recon' in cat_name:
                        stats['recon_events'] += 1
                    elif 'backdoor' in cat_name:
                        stats['backdoor_events'] += 1
                    elif 'analysis' in cat_name:
                        stats['analysis_events'] += 1

            history = self.connection_history[srcip]
            history.append((stime, dstip, dsport))
            
            while history and (stime - history[0][0] > self.window_size):
                history.popleft()
            
            current_window_ips = set()
            current_window_ports = set()
            current_window_ip_ports = defaultdict(set)
            
            for t, d_ip, d_port in history:
                current_window_ips.add(d_ip)
                if d_port != -1:
                    current_window_ports.add(d_port)
                    current_window_ip_ports[d_ip].add(d_port)
            
            max_ports_per_ip = max([len(ports) for ports in current_window_ip_ports.values()]) if current_window_ip_ports else 0
            
            stats['peak_window_dst_ips'] = max(stats['peak_window_dst_ips'], len(current_window_ips))
            stats['peak_window_dst_ports'] = max(stats['peak_window_dst_ports'], len(current_window_ports))
            stats['peak_window_ports_per_ip'] = max(stats['peak_window_ports_per_ip'], max_ports_per_ip)

    def analyze(self, file_path, chunk_size=100000):
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
            
        print(f"Starting analysis on {file_path}...")
        start_time = time.time()
        
        is_headered, col_mapping = self.detect_headers_and_indices(file_path)
        print(f"CSV Format: {'Headered' if is_headered else 'Headerless'}")
        print("Column mapping:", col_mapping)
        
        chunk_count = 0
        total_rows = 0
        
        header_param = 0 if is_headered else None
        
        for chunk in pd.read_csv(file_path, header=header_param, chunksize=chunk_size, low_memory=False, encoding='cp1252'):
            self.process_chunk(chunk, col_mapping, is_headered)
            chunk_count += 1
            total_rows += len(chunk)
            print(f"Processed chunk {chunk_count} ({total_rows} rows parsed)...")
            
        duration = time.time() - start_time
        print(f"Analysis completed in {duration:.2f} seconds. Parsed {total_rows} records.")
        return total_rows

    def classify_ip(self, ip, stats):
        reasons = []
        is_suspicious = False
        scan_type = None
        severity = "Low"
        
        time_span = stats['last_seen'] - stats['first_seen']
        flow_rate = stats['total_flows'] / max(time_span, 1.0)
        
        if stats['peak_window_ports_per_ip'] >= self.vertical_threshold:
            is_suspicious = True
            scan_type = "Vertical Port Scan"
            reasons.append(f"Scanned {stats['peak_window_ports_per_ip']} unique ports on a single host in a {self.window_size}s window")
            severity = "High"
            
        elif stats['peak_window_dst_ips'] >= self.horizontal_threshold:
            is_suspicious = True
            scan_type = "Horizontal Port Scan"
            reasons.append(f"Scanned {stats['peak_window_dst_ips']} unique destination IPs in a {self.window_size}s window")
            severity = "High"
            
        elif (stats['peak_window_dst_ips'] >= self.strobe_ips_threshold and 
              stats['peak_window_dst_ports'] >= self.strobe_ports_threshold):
            is_suspicious = True
            scan_type = "Strobe Port Scan"
            reasons.append(f"Strobe scan detected: {stats['peak_window_dst_ips']} hosts and {stats['peak_window_dst_ports']} ports scanned in a {self.window_size}s window")
            severity = "High"
            
        elif flow_rate >= self.rate_threshold and stats['total_flows'] >= 50:
            is_suspicious = True
            scan_type = "High-Rate Connection Anomaly"
            reasons.append(f"High flow rate: {flow_rate:.2f} connections/sec (total connections: {stats['total_flows']})")
            severity = "Medium"
            
        total_failed = stats['states']['REQ'] + stats['states']['INT'] + stats['states']['RST']
        failed_ratio = total_failed / max(stats['total_flows'], 1.0)
        if stats['total_flows'] >= 30 and failed_ratio > 0.85 and len(stats['unique_dst_ports']) >= 10:
            is_suspicious = True
            scan_type = "Stealth Scan (High Failed Conn Ratio)"
            reasons.append(f"High ratio of failed/interrupted connections: {failed_ratio:.1%} (total: {stats['total_flows']})")
            severity = "Medium"

        classification = "Normal"
        
        if is_suspicious:
            classification = f"Suspicious ({scan_type})"
        elif stats['backdoor_events'] > 0:
            classification = "Suspicious (Backdoor)"
            reasons.append(f"Labeled backdoor activity in dataset ({stats['backdoor_events']} flows)")
            severity = "Critical"
        elif stats['analysis_events'] > 0:
            classification = "Suspicious (Analysis)"
            reasons.append(f"Labeled analysis/exploring activity in dataset ({stats['analysis_events']} flows)")
            severity = "Medium"
        elif stats['labeled_attacks'] > 0:
            primary_cat = max(stats['attack_categories'], key=stats['attack_categories'].get, default="Other")
            classification = f"Suspicious (Attack: {primary_cat.capitalize()})"
            reasons.append(f"Labeled attack traffic in dataset ({stats['labeled_attacks']} flows)")
            severity = "High"

        if classification == "Normal":
            c2_ports = {4444, 6667, 8000, 8080, 9999}
            contacted_c2_ports = stats['unique_dst_ports'].intersection(c2_ports)
            if contacted_c2_ports and stats['total_flows'] < 20:
                classification = "Suspicious (Backdoor Heuristic)"
                reasons.append(f"Quiet connection established to potential C2 port(s): {list(contacted_c2_ports)}")
                severity = "Medium"

        return {
            'classification': classification,
            'is_suspicious': classification != "Normal",
            'severity': severity if classification != "Normal" else "Info",
            'reasons': reasons
        }

    def get_results_df(self):
        records = []
        for ip, stats in self.ip_stats.items():
            cls_details = self.classify_ip(ip, stats)
            time_span = stats['last_seen'] - stats['first_seen']
            flow_rate = stats['total_flows'] / max(time_span, 1.0)
            
            # Convert sets to sorted lists for json compatibility
            protocols_list = sorted(list(stats['protocols']))
            services_list = sorted(list(stats['services']))
            
            records.append({
                'source_ip': ip,
                'total_connections': stats['total_flows'],
                'unique_destinations': len(stats['unique_dst_ips']),
                'unique_ports': len(stats['unique_dst_ports']),
                'total_bytes': stats['total_bytes'],
                'total_packets': stats['total_pkts'],
                'duration_sec': round(time_span, 2),
                'conn_rate_per_sec': round(flow_rate, 2),
                'peak_window_ips': stats['peak_window_dst_ips'],
                'peak_window_ports': stats['peak_window_dst_ports'],
                'peak_ports_per_ip': stats['peak_window_ports_per_ip'],
                'protocols': protocols_list,
                'services': services_list,
                'states': dict(stats['states']),
                
                # Classification
                'classification': cls_details['classification'],
                'is_suspicious': cls_details['is_suspicious'],
                'severity': cls_details['severity'],
                'reason': "; ".join(cls_details['reasons']) if cls_details['reasons'] else "Normal traffic behavior",
                
                'labeled_attacks_count': stats['labeled_attacks'],
                'true_attack_cat': max(stats['attack_categories'], key=stats['attack_categories'].get, default="None") if stats['labeled_attacks'] > 0 else "None"
            })
            
        if not records:
            return pd.DataFrame(columns=[
                'source_ip', 'total_connections', 'unique_destinations', 'unique_ports',
                'total_bytes', 'total_packets', 'duration_sec', 'conn_rate_per_sec',
                'peak_window_ips', 'peak_window_ports', 'peak_ports_per_ip',
                'protocols', 'services', 'states',
                'classification', 'is_suspicious', 'severity', 'reason',
                'labeled_attacks_count', 'true_attack_cat'
            ])
        df = pd.DataFrame(records)
        if not df.empty:
            df = df.sort_values(by=['is_suspicious', 'total_connections'], ascending=[False, False]).reset_index(drop=True)
        return df
