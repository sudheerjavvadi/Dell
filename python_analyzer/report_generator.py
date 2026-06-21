import os
import json
import pandas as pd


class ReportGenerator:
    def __init__(self, results_df):
        self.df = results_df
        # Filter for suspicious records
        self.suspicious_df = self.df[self.df['is_suspicious'] == True].reset_index(drop=True)

    def export_csv(self, output_path):
        """Export suspicious IPs to a CSV file."""
        self.suspicious_df.to_csv(output_path, index=False)
        print(f"Suspicious IP list exported to CSV: {output_path}")

    def export_json(self, output_path, dataset_name="Network Traffic Capture"):
        """Export the analysis results as a JSON file for the React dashboard."""
        total_ips = len(self.df)
        suspicious_ips = len(self.suspicious_df)
        normal_ips = total_ips - suspicious_ips

        severity_counts = self.df['severity'].value_counts()
        critical_count = int(severity_counts.get('Critical', 0))
        high_count     = int(severity_counts.get('High', 0))
        medium_count   = int(severity_counts.get('Medium', 0))
        info_count     = int(severity_counts.get('Info', 0)) + int(severity_counts.get('Low', 0))

        # Convert DataFrames to records (handle boolean/numpy types)
        df_copy = self.df.copy()
        df_copy['is_suspicious'] = df_copy['is_suspicious'].astype(bool)

        susp_copy = self.suspicious_df.copy()
        susp_copy['is_suspicious'] = susp_copy['is_suspicious'].astype(bool)

        all_hosts       = df_copy.to_dict(orient='records')
        suspicious_hosts = susp_copy.to_dict(orient='records')

        report_data = {
            'dataset_name': os.path.basename(dataset_name),
            'summary': {
                'total_ips': total_ips,
                'suspicious_ips': suspicious_ips,
                'normal_ips': normal_ips,
                'severity_distribution': {
                    'Critical': critical_count,
                    'High':     high_count,
                    'Medium':   medium_count,
                    'Normal':   info_count
                }
            },
            'hosts': all_hosts,
            'suspicious_hosts': suspicious_hosts
        }

        # Ensure output directory exists
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2)
        print(f"Analysis JSON exported to React dashboard: {output_path}")
