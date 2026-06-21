import os
import pandas as pd
from collections import defaultdict, deque
from analyzer import PortScanAnalyzer

class AdvancedPortScanAnalyzer(PortScanAnalyzer):
    def __init__(self, 
                 window_size=60, 
                 vertical_threshold=20, 
                 horizontal_threshold=30, 
                 strobe_ips_threshold=10, 
                 strobe_ports_threshold=10, 
                 rate_threshold=10,
                 slow_ports_threshold=10,
                 slow_rate_max=0.05,
                 campaign_window=300,
                 campaign_min_ips=3,
                 common_ports_hosts=5):
        
        super().__init__(window_size, 
                         vertical_threshold, 
                         horizontal_threshold, 
                         strobe_ips_threshold, 
                         strobe_ports_threshold, 
                         rate_threshold)
        
        # Advanced configs
        self.slow_ports_threshold = slow_ports_threshold
        self.slow_rate_max = slow_rate_max
        self.campaign_window = campaign_window
        self.campaign_min_ips = campaign_min_ips
        self.common_ports_hosts = common_ports_hosts
        
        # Global targets tracking for Distributed Campaigns
        # (dstip, dsport) -> list of (timestamp, srcip)
        self.target_port_hits = defaultdict(list)
        
        # Keep track of which srcips targeted which target hosts
        # dstip -> set of srcips
        self.target_ips_srcs = defaultdict(set)
        
        # Keep track of distributed scan campaign flags
        # srcip -> set of (dstip, dsport) involved in campaign
        self.campaign_flags = defaultdict(set)

    def process_chunk(self, chunk, col_mapping, is_headered):
        # Run standard analytics first
        super().process_chunk(chunk, col_mapping, is_headered)

        # For headered CSVs: normalize col names. For headerless: use int indices directly.
        def _col(name, default):
            raw = col_mapping.get(name, default if not is_headered else None)
            return self._norm_col(raw) if is_headered else raw

        srcip_col  = _col('srcip',  0)
        dstip_col  = _col('dstip',  2)
        dsport_col = _col('dsport', 3)
        stime_col  = _col('stime',  28)
        state_col  = _col('state',  5)

        row_len = len(chunk.columns)
        for row in chunk.itertuples(index=False):
            try:
                if is_headered:
                    srcip  = getattr(row, srcip_col)  if srcip_col  else None
                    dstip  = getattr(row, dstip_col)  if dstip_col  else None
                    dsport = getattr(row, dsport_col) if dsport_col else None
                    stime  = getattr(row, stime_col)  if stime_col  else 0.0
                    state  = getattr(row, state_col)  if state_col  else 'unknown'
                else:
                    srcip  = row[srcip_col]  if srcip_col  is not None and srcip_col  < row_len else None
                    dstip  = row[dstip_col]  if dstip_col  is not None and dstip_col  < row_len else None
                    dsport = row[dsport_col] if dsport_col is not None and dsport_col < row_len else None
                    stime  = row[stime_col]  if stime_col  is not None and stime_col  < row_len else 0.0
                    state  = row[state_col]  if state_col  is not None and state_col  < row_len else 'unknown'
            except (IndexError, AttributeError):
                continue
                
            if pd.isna(srcip) or pd.isna(dstip):
                continue
                
            srcip = str(srcip).strip()
            dstip = str(dstip).strip()
            state = str(state).strip().upper()
            dsport = self.parse_port(dsport)
            try:
                stime = float(stime)
            except ValueError:
                continue
                
            if dsport != -1:
                # 1. Distributed Campaigns Tracking (Stealth scans only)
                if state in {'REQ', 'INT', 'RST'}:
                    hits = self.target_port_hits[(dstip, dsport)]
                    hits.append((stime, srcip))
                    
                    # Purge hits older than campaign window
                    while hits and (stime - hits[0][0] > self.campaign_window):
                        hits.pop(0)
                        
                    # Find unique source IPs targeting this port within the window
                    unique_srcs = {h[1] for h in hits}
                    if len(unique_srcs) >= self.campaign_min_ips:
                        # Flag this as a coordinated campaign
                        for hit_time, hit_src in hits:
                            self.campaign_flags[hit_src].add((dstip, dsport))
                
                # Track unique source IPs per destination host
                self.target_ips_srcs[dstip].add(srcip)

    def classify_ip(self, ip, stats):
        # We restore the base rules completely so they are the primary metrics
        return super().classify_ip(ip, stats)

    def classify_ip_advanced(self, ip, stats):
        time_span = stats['last_seen'] - stats['first_seen']
        flow_rate = stats['total_flows'] / max(time_span, 1.0)
        
        # Common Ports List (Highly targeted by scanners)
        common_scan_ports = {21, 22, 23, 80, 443, 445, 1433, 3306, 3389, 8080}
        contacted_common_ports = stats['unique_dst_ports'].intersection(common_scan_ports)
        
        avg_bytes_per_flow = stats['total_bytes'] / max(stats['total_flows'], 1.0)
        avg_pkts_per_flow = stats['total_pkts'] / max(stats['total_flows'], 1.0)
        
        # Benign service profile: high average packet/byte volumes, but very few unique destination ports (not scanning)
        is_high_volume = (avg_bytes_per_flow > 100000 and 
                          avg_pkts_per_flow > 200 and 
                          len(stats['unique_dst_ports']) < 5)
        
        involved_targets = self.campaign_flags[ip]
        
        is_slow_scanning = (len(stats['unique_dst_ports']) >= self.slow_ports_threshold and 
                            flow_rate <= self.slow_rate_max and 
                            time_span >= 300)
                            
        # Common Ports Probing (only checked if the host has base classification as Normal)
        base_result = super().classify_ip(ip, stats)
        is_common_ports_probe = (len(contacted_common_ports) >= 3 and 
                                 len(stats['unique_dst_ips']) >= self.common_ports_hosts and 
                                 base_result['classification'] == "Normal")

        adv_classification = "Normal Traffic"
        adv_reason = "No advanced threat signatures detected"
        
        if is_high_volume and base_result['classification'] != "Normal" and "Attack" not in base_result['classification']:
            adv_classification = "Benign Service / Crawler"
            adv_reason = f"High payload density profile: {avg_bytes_per_flow:.0f} B/flow, {avg_pkts_per_flow:.1f} pkts/flow. Potential NIDS false positive."
        elif len(involved_targets) >= 3:
            adv_classification = "Distributed Scan Campaign"
            target_hosts = list({t[0] for t in involved_targets})[:3]
            adv_reason = f"Distributed Scan: Coordinated probe against target ports across {len(involved_targets)} destinations (Targets: {target_hosts})"
        elif is_slow_scanning:
            adv_classification = "Slow Port Scan"
            adv_reason = f"Slow scanning detected: targeted {len(stats['unique_dst_ports'])} ports over {time_span:.1f}s at rate {flow_rate:.3f} conns/sec"
        elif is_common_ports_probe:
            adv_classification = "Common Ports Probe"
            adv_reason = f"Common targeted ports scanned: targeted ports {list(contacted_common_ports)} across {len(stats['unique_dst_ips'])} distinct hosts"
        elif base_result['is_suspicious']:
            adv_classification = "Standard Port Scan (Single Host)"
            adv_reason = "Participated in high-rate or threshold-based port scans"

        return {
            'advanced_classification': adv_classification,
            'advanced_reason': adv_reason
        }

    def get_results_df(self):
        records = []
        for ip, stats in self.ip_stats.items():
            base_details = self.classify_ip(ip, stats)
            adv_details = self.classify_ip_advanced(ip, stats)
            
            time_span = stats['last_seen'] - stats['first_seen']
            flow_rate = stats['total_flows'] / max(time_span, 1.0)
            
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
                
                # Primary Classification (Baseline rule engine)
                'classification': base_details['classification'],
                'is_suspicious': base_details['is_suspicious'],
                'severity': base_details['severity'],
                'reason': "; ".join(base_details['reasons']) if base_details['reasons'] else "Normal traffic behavior",
                
                # Advanced Correlation (Appended advanced heuristics)
                'advanced_classification': adv_details['advanced_classification'],
                'advanced_reason': adv_details['advanced_reason'],
                
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
                'advanced_classification', 'advanced_reason',
                'labeled_attacks_count', 'true_attack_cat'
            ])
            
        df = pd.DataFrame(records)
        if not df.empty:
            df = df.sort_values(by=['is_suspicious', 'total_connections'], ascending=[False, False]).reset_index(drop=True)
        return df
