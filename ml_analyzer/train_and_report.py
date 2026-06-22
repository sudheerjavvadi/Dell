import os
import json
import pandas as pd
import numpy as np
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler

def main():
    print("[*] Starting ML Model Training & Reporting Pipeline...")
    
    archive_dir = os.path.join(os.path.dirname(__file__), "..", "python_analyzer", "archive")
    train_file = os.path.join(archive_dir, "UNSW_NB15_training-set.csv")
    test_file = os.path.join(archive_dir, "UNSW_NB15_testing-set.csv")
    analyze_file = os.path.join(archive_dir, "UNSW-NB15_2.csv")
    
    if not os.path.exists(train_file) or not os.path.exists(analyze_file):
        print("[-] Required datasets not found in archive.")
        return

    print("[*] Loading training dataset...")
    train_df = pd.read_csv(train_file)
    
    # We will read analyze_file in chunks to avoid memory issues and parse its columns
    analyze_cols = [
        'srcip', 'sport', 'dstip', 'dsport', 'proto', 'state', 'dur', 'sbytes', 'dbytes',
        'sttl', 'dttl', 'sloss', 'dloss', 'service', 'sload', 'dload', 'spkts', 'dpkts',
        'swin', 'dwin', 'stcpb', 'dtcpb', 'smean', 'dmean', 'trans_depth', 'response_body_len',
        'sjit', 'djit', 'Stime', 'Ltime', 'sinpkt', 'dinpkt', 'tcprtt', 'synack', 'ackdat',
        'is_sm_ips_ports', 'ct_state_ttl', 'ct_flw_http_mthd', 'is_ftp_login', 'ct_ftp_cmd',
        'ct_srv_src', 'ct_srv_dst', 'ct_dst_ltm', 'ct_src_ltm', 'ct_src_dport_ltm',
        'ct_dst_sport_ltm', 'ct_dst_src_ltm', 'attack_cat', 'label'
    ]
    
    print("[*] Loading UNSW-NB15_2.csv for analysis (sample)...")
    # Read the whole file and sample it to get a mix of normal and attack traffic
    analyze_df = pd.read_csv(analyze_file, names=analyze_cols, header=None)
    analyze_df = analyze_df.sample(50000, random_state=42).reset_index(drop=True)

    # Convert analyze_df column types to numeric where possible, coercing errors
    for c in analyze_cols:
        if c not in ['srcip', 'dstip', 'proto', 'state', 'service', 'attack_cat']:
            analyze_df[c] = pd.to_numeric(analyze_df[c], errors='coerce').fillna(0)

    # In the training set, we have some columns. Let's find common numeric columns.
    # We also have to handle 'rate' which might be missing in analyze_df.
    if 'rate' not in analyze_df.columns:
        analyze_df['rate'] = 0 # Dummy if not present

    numeric_cols = train_df.select_dtypes(include=[np.number]).columns.tolist()
    features = [c for c in numeric_cols if c in analyze_df.columns and c not in ['id', 'label', 'Stime', 'Ltime']]
    
    print(f"[*] Selected {len(features)} numeric features for training.")
    
    X_train = train_df[features].fillna(0)
    y_train = train_df['label']
    
    # Scale features
    print("[*] Scaling features...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    
    # Train Deep Learning Model (MLP)
    print("[*] Training Deep Learning Model (MLPClassifier)...")
    # We use fewer iterations to make it faster for this demo
    model = MLPClassifier(hidden_layer_sizes=(32,), max_iter=10, random_state=42, verbose=False)
    model.fit(X_train_scaled, y_train)
    
    # Generate Dashboard JSON from the Analyze DataFrame (UNSW-NB15_2.csv)
    print("[*] Running inference on UNSW-NB15_2.csv and synthesizing React Dashboard Report...")
    
    X_analyze = analyze_df[features].fillna(0)
    X_analyze_scaled = scaler.transform(X_analyze)
    
    analyze_preds = model.predict(X_analyze_scaled)
    analyze_probs = model.predict_proba(X_analyze_scaled)[:, 1]
    
    # Group by srcip
    analyze_df['predicted_label'] = analyze_preds
    analyze_df['predicted_prob'] = analyze_probs
    
    hosts = []
    suspicious_hosts = []
    
    critical_count = 0
    high_count = 0
    medium_count = 0
    normal_count = 0
    
    # Group by srcip and build the report
    grouped = analyze_df.groupby('srcip')
    
    for srcip, group in grouped:
        conns = len(group)
        unique_dsts = group['dstip'].nunique()
        unique_ports = group['dsport'].nunique() if 'dsport' in group.columns else 1
        total_bytes = int(group['sbytes'].sum() + group['dbytes'].sum())
        total_pkts = int(group['spkts'].sum() + group['dpkts'].sum())
        
        # Calculate duration
        dur = float(group['dur'].sum())
        rate = conns / dur if dur > 0 else conns
        
        # Get highest probability
        max_prob = group['predicted_prob'].max()
        is_suspicious = bool(max_prob > 0.5)
        
        if not is_suspicious:
            severity = "Normal"
            normal_count += 1
        elif max_prob > 0.9:
            severity = "Critical"
            critical_count += 1
        elif max_prob > 0.7:
            severity = "High"
            high_count += 1
        else:
            severity = "Medium"
            medium_count += 1
            
        # Get actual attack category (if any) to show in report
        attack_cats = [c for c in group['attack_cat'].unique() if isinstance(c, str) and c.strip()]
        attack_cat = attack_cats[0] if attack_cats else "ML_Detected_Anomaly" if is_suspicious else "Normal"
        
        # Get protocols
        protos = group['proto'].unique().tolist()
        states = group['state'].value_counts().to_dict()
        
        host_record = {
            "source_ip": str(srcip),
            "total_connections": int(conns),
            "unique_destinations": int(unique_dsts),
            "unique_ports": int(unique_ports),
            "total_bytes": total_bytes,
            "total_packets": total_pkts,
            "duration_sec": round(dur, 2),
            "conn_rate_per_sec": round(rate, 2),
            "severity": severity,
            "classification": attack_cat,
            "is_suspicious": is_suspicious,
            "reason": f"Deep Learning Model predicted malicious flow with {(max_prob*100):.1f}% max confidence.",
            "advanced_classification": "Deep Learning Anomaly" if is_suspicious else "Normal Traffic",
            "advanced_reason": "Neural Network detected anomalies in flow patterns." if is_suspicious else "No anomalies detected.",
            "states": states,
            "protocols": protos
        }
        
        hosts.append(host_record)
        if is_suspicious:
            suspicious_hosts.append(host_record)
            
    report_data = {
        'dataset_name': 'UNSW-NB15_2.csv (ML Analysis)',
        'summary': {
            'total_ips': len(hosts),
            'suspicious_ips': len(suspicious_hosts),
            'normal_ips': normal_count,
            'severity_distribution': {
                'Critical': critical_count,
                'High': high_count,
                'Medium': medium_count,
                'Normal': normal_count
            }
        },
        'hosts': hosts,
        'suspicious_hosts': suspicious_hosts
    }
    
    out_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "react_dashboard", "public"))
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "ml_report_data.json")
    
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(report_data, f, indent=2)
        
    print(f"[+] Execution finished successfully!")
    print(f"    ML React Dashboard Data: {out_path}")

if __name__ == "__main__":
    main()
