import os
import sys
import argparse
from analyzer import PortScanAnalyzer
from advanced_analyzer import AdvancedPortScanAnalyzer
from report_generator import ReportGenerator

HEADER = """
================================================================================
███╗   ██╗███████╗████████╗██╗    ██╗ ██████╗ ██████╗ ██╗  ██╗
████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔═══██╗██╔══██╗██║  ██║
██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║██║   ██║██████╔╝███████║
██║╚██╗██║██╔══╝     ██║   ██║███╗██║██║   ██║██╔══██╗██╔══██║
██║ ╚████║███████╗   ██║   ╚███╔███╔╝╚██████╔╝██║  ██║██║  ██║
╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
██████╗  ██████╗ ██╗   ██╗███╗   ██╗ ██████╗███████╗██████╗ 
██╔══██╗██╔═══██╗██║   ██║████╗  ██║██╔════╝██╔════╝██╔══██╗
██████╔╝██║   ██║██║   ██║██╔██╗ ██║██║     █████╗  ██████╔╝
██╔══██╗██║   ██║██║   ██║██║╚██╗██║██║     ██╔══╝  ██╔══██╗
██████╔╝╚██████╔╝╚██████╔╝██║ ╚████║╚██████╗███████╗██║  ██║
╚══════╝  ╚═════╝  ╚══════╝ ╚═╝  ╚═══╝ ╚══════╝╚══════╝╚═╝  ╚═╝
  Detecting Suspicious Port Scanning in Data Center Traffic
================================================================================
"""

def print_summary_table(df):
    """Print a clean 'Suspicious Activity Detected' report to the console."""
    if df.empty:
        print("\n[+] All Clear: No suspicious activities detected in the dataset.")
        return

    suspicious = df[df['is_suspicious'] == True]
    if suspicious.empty:
        print("\n[+] All Clear: No suspicious activities detected in the dataset.")
        return

    # ── Header ──────────────────────────────────────────────────────────────
    print("\n" + "=" * 65)
    print("  SUSPICIOUS ACTIVITY REPORT")
    print("  The Network Bouncer — Rule-Based NIDS")
    print("=" * 65)
    print(f"  Total Suspicious IPs Flagged: {len(suspicious)}")
    print("=" * 65)

    for idx, (_, row) in enumerate(suspicious.head(20).iterrows(), start=1):
        ip          = row['source_ip']
        conns       = int(row['total_connections'])
        dsts        = int(row['unique_destinations'])
        ports       = int(row['unique_ports'])
        severity    = row['severity']
        cls         = row['classification']
        rate        = row.get('conn_rate_per_sec', 0)
        reason      = row.get('reason', '')
        adv_cls     = row.get('advanced_classification', '')
        duration    = row.get('duration_sec', 0)
        bytes_total = int(row.get('total_bytes', 0))

        # Severity color marker
        sev_mark = {
            'Critical': '[!!!]',
            'High':     '[!!] ',
            'Medium':   '[!]  ',
        }.get(severity, '[i]  ')

        print(f"\n  {idx}. Suspicious Activity Detected: {sev_mark} {severity.upper()} SEVERITY")
        print(f"  {'-' * 60}")
        print(f"    Source IP             : {ip}")
        print(f"    Connections           : {conns:,}")
        print(f"    Unique Destinations   : {dsts}")
        print(f"    Unique Ports Targeted : {ports}")
        print(f"    Connection Rate       : {rate:.2f} conns/sec")
        print(f"    Observation Window    : {duration:.1f} seconds")
        print(f"    Total Data Volume     : {bytes_total / 1024:.1f} KB")
        print(f"    Classification        : {cls}")
        if adv_cls and adv_cls not in ('Normal Traffic', ''):
            print(f"    Advanced Correlation  : {adv_cls}")
        if reason:
            # Wrap long reasons
            for i, r in enumerate(reason.split('; ')):
                label = "    Detection Reason     :" if i == 0 else "                         "
                print(f"{label} {r}")
        print()

    print("=" * 65)
    if len(suspicious) > 20:
        print(f"  ... and {len(suspicious) - 20} more suspicious IP(s) — see CSV/JSON reports.")
    print("  Run completed. Full reports saved to CSV and JSON.")
    print("=" * 65)

def main():
    # Configure stdout to handle UTF-8 symbols in the Windows console
    if hasattr(sys.stdout, 'reconfigure'):
        try:
            sys.stdout.reconfigure(encoding='utf-8')
        except Exception:
            pass
    print(HEADER)
    
    parser = argparse.ArgumentParser(description="The Network Bouncer: Detect port scanning from netflow CSV.")
    parser.add_argument("file_path", help="Path to the network logs CSV file.")
    
    # Heuristic detection arguments
    parser.add_argument("--window", type=int, default=60, help="Sliding time window in seconds (default: 60)")
    parser.add_argument("--vertical", type=int, default=20, help="Vertical scan threshold: unique ports on a host (default: 20)")
    parser.add_argument("--horizontal", type=int, default=30, help="Horizontal scan threshold: unique hosts scanned (default: 30)")
    parser.add_argument("--strobe-ips", type=int, default=10, help="Strobe scan IP threshold (default: 10)")
    parser.add_argument("--strobe-ports", type=int, default=10, help="Strobe scan Port threshold (default: 10)")
    parser.add_argument("--rate", type=int, default=10, help="High connection rate threshold (default: 10 conns/sec)")
    
    # Advanced detection arguments
    parser.add_argument("--slow-ports", type=int, default=10, help="Slow scan port threshold (default: 10)")
    parser.add_argument("--slow-rate", type=float, default=0.05, help="Slow scan max connection rate threshold (default: 0.05)")
    parser.add_argument("--campaign-window", type=int, default=300, help="Distributed scan campaign window in seconds (default: 300)")
    parser.add_argument("--campaign-ips", type=int, default=3, help="Minimum IPs in distributed scan campaign (default: 3)")
    parser.add_argument("--common-ports-hosts", type=int, default=5, help="Minimum distinct hosts for common ports scan (default: 5)")
    
    # Output file arguments
    parser.add_argument("--csv", default="suspicious_ips_report.csv", help="Path to output CSV report (default: suspicious_ips_report.csv)")
    parser.add_argument("--json", default="../react_dashboard/public/report_data.json", help="Path to output JSON for the React dashboard (default: ../react_dashboard/public/report_data.json)")
    parser.add_argument("--chunk-size", type=int, default=100000, help="Rows per processing chunk (default: 100000)")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.file_path):
        print(f"[-] Error: File '{args.file_path}' does not exist.")
        sys.exit(1)
        
    print(f"[*] Starting Network Analyzer...")
    print(f"[*] Parameters:")
    print(f"    - Sliding Window: {args.window} seconds")
    print(f"    - Vertical Scan Threshold: {args.vertical} ports")
    print(f"    - Horizontal Scan Threshold: {args.horizontal} hosts")
    print(f"    - Strobe Scan Threshold: {args.strobe_ips} IPs & {args.strobe_ports} Ports")
    print(f"    - Connection Rate Threshold: {args.rate} per second")
    print(f"    - Advanced: Slow scan (ports >= {args.slow_ports}, rate <= {args.slow_rate})")
    print(f"    - Advanced: Coordinated scan campaign window: {args.campaign_window}s, min IPs: {args.campaign_ips}")
    print(f"    - Advanced: Common ports scan min hosts: {args.common_ports_hosts}")
    print(f"    - Reading in chunks of {args.chunk_size} rows")
    print("-" * 80)
    
    analyzer = AdvancedPortScanAnalyzer(
        window_size=args.window,
        vertical_threshold=args.vertical,
        horizontal_threshold=args.horizontal,
        strobe_ips_threshold=args.strobe_ips,
        strobe_ports_threshold=args.strobe_ports,
        rate_threshold=args.rate,
        slow_ports_threshold=args.slow_ports,
        slow_rate_max=args.slow_rate,
        campaign_window=args.campaign_window,
        campaign_min_ips=args.campaign_ips,
        common_ports_hosts=args.common_ports_hosts
    )
    
    try:
        total_rows = analyzer.analyze(args.file_path, chunk_size=args.chunk_size)
    except Exception as e:
        print(f"[-] Analysis error: {e}")
        sys.exit(1)
        
    results_df = analyzer.get_results_df()
    
    suspicious_count = len(results_df[results_df['is_suspicious'] == True])
    print(f"\n[+] Processing complete!")
    print(f"[+] Analyzed {total_rows:,} flow records.")
    print(f"[+] Identified {len(results_df):,} distinct Source IPs.")
    print(f"[+] Flagged {suspicious_count:,} Source IPs as Suspicious.")
    
    print_summary_table(results_df)
    
    print("\n[*] Writing reports...")
    generator = ReportGenerator(results_df)
    generator.export_csv(args.csv)
    generator.export_json(args.json, dataset_name=args.file_path)
    
    print("\n[+] Execution finished successfully!")
    print(f"    CSV Report:       {os.path.abspath(args.csv)}")
    print(f"    React Dashboard:  {os.path.abspath(args.json)}")
    print("\n[*] Open the React dashboard to view results:")
    print("    cd react_dashboard && npm run dev  →  http://localhost:5173/")
    print("================================================================================\n")

if __name__ == "__main__":
    main()
