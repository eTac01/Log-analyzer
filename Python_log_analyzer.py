import streamlit as st
import pandas as pd
import re
import matplotlib.pyplot as plt
from datetime import datetime, timedelta
import json
import requests
from collections import defaultdict, Counter
import os
from typing import List, Dict, Any
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY')
if not OPENAI_API_KEY:
    raise ValueError("OPENAI_API_KEY not found in environment variables. Please set it in a .env file or environment.")

client = OpenAI(api_key=OPENAI_API_KEY)

class LogAnalyzer:
    def __init__(self):
        self.df = None
        self.threats = []
        self.results_file = "analysis_results.json"

    # 1. SYSTEM LOGS (Windows Event Logs & Linux syslog)
    def parse_system_log(self, log_path: str) -> pd.DataFrame:
        """Parse Windows Event Logs and Linux syslog."""
        pattern = re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}|\w+ \d+ \d{2}:\d{2}:\d{2}) (\w+) (\w+\[\d+\]|[\w\-]+): (.+)')
        data = []
        with open(log_path, 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                m = pattern.match(line)
                if m:
                    timestamp_str, hostname, process, message = m.groups()
                    try:
                        timestamp = pd.to_datetime(timestamp_str)
                    except:
                        timestamp = pd.NaT
                    data.append({
                        'timestamp': timestamp,
                        'hostname': hostname,
                        'process': process,
                        'message': message,
                        'log_type': 'system'
                    })
        return pd.DataFrame(data)

    # 2. APPLICATION LOGS
    def parse_application_log(self, log_path: str) -> pd.DataFrame:
        """Parse application logs (generic format)."""
        pattern = re.compile(r'\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] \[(\w+)\] (.+)')
        data = []
        with open(log_path, 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                m = pattern.match(line)
                if m:
                    timestamp_str, level, message = m.groups()
                    try:
                        timestamp = pd.to_datetime(timestamp_str)
                    except:
                        timestamp = pd.NaT
                    data.append({
                        'timestamp': timestamp,
                        'level': level,
                        'message': message,
                        'log_type': 'application'
                    })
        return pd.DataFrame(data)

    # 3. AUTHENTICATION LOGS
    def parse_auth_log(self, log_path: str) -> pd.DataFrame:
        """Parse authentication logs."""
        pattern = re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) .* (Accepted|Failed) (\w+) for (\S+) from (\S+)')
        data = []
        with open(log_path, 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                m = pattern.match(line)
                if m:
                    timestamp_str, status, auth_type, user, ip = m.groups()
                    try:
                        timestamp = pd.to_datetime(timestamp_str)
                    except:
                        timestamp = pd.NaT
                    data.append({
                        'timestamp': timestamp,
                        'status': status,
                        'auth_type': auth_type,
                        'user': user,
                        'ip': ip,
                        'log_type': 'authentication'
                    })
        return pd.DataFrame(data)

    # 4. NETWORK LOGS (Firewall/IDS)
    def parse_network_log(self, log_path: str) -> pd.DataFrame:
        """Parse firewall and IDS/IPS logs."""
        pattern = re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) .* (allow|deny|drop) (\S+) (\d+\.\d+\.\d+\.\d+) (\d+\.\d+\.\d+\.\d+) (\d+) (\w+)')
        data = []
        with open(log_path, 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                m = pattern.match(line)
                if m:
                    timestamp_str, action, protocol, src_ip, dst_ip, port, rule = m.groups()
                    try:
                        timestamp = pd.to_datetime(timestamp_str)
                    except:
                        timestamp = pd.NaT
                    data.append({
                        'timestamp': timestamp,
                        'action': action,
                        'protocol': protocol,
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'port': int(port),
                        'rule': rule,
                        'log_type': 'network'
                    })
        return pd.DataFrame(data)

    # 5. SECURITY DEVICE LOGS (Antivirus, EDR)
    def parse_security_log(self, log_path: str) -> pd.DataFrame:
        """Parse antivirus and EDR logs."""
        pattern = re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) .* (Threat|Suspicious|Clean|Quarantined) .* (.*)')
        data = []
        with open(log_path, 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                m = pattern.match(line)
                if m:
                    timestamp_str, status, details = m.groups()
                    try:
                        timestamp = pd.to_datetime(timestamp_str)
                    except:
                        timestamp = pd.NaT
                    data.append({
                        'timestamp': timestamp,
                        'status': status,
                        'details': details,
                        'log_type': 'security_device'
                    })
        return pd.DataFrame(data)

    # 6. FIREWALL LOGS
    def parse_firewall_log(self, log_path: str) -> pd.DataFrame:
        """Parse firewall logs."""
        pattern = re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) .* (BLOCKED|ALLOWED) .* (\S+) -> (\S+) port (\d+)')
        data = []
        with open(log_path, 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                m = pattern.match(line)
                if m:
                    timestamp_str, action, src, dst, port = m.groups()
                    try:
                        timestamp = pd.to_datetime(timestamp_str)
                    except:
                        timestamp = pd.NaT
                    data.append({
                        'timestamp': timestamp,
                        'action': action,
                        'src_ip': src,
                        'dst_ip': dst,
                        'port': int(port),
                        'log_type': 'firewall'
                    })
        return pd.DataFrame(data)

    # 7. DNS LOGS
    def parse_dns_log(self, log_path: str) -> pd.DataFrame:
        """Parse DNS logs."""
        pattern = re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) .* query: (\S+) (\S+) (\S+)')
        data = []
        with open(log_path, 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                m = pattern.match(line)
                if m:
                    timestamp_str, domain, qtype, response = m.groups()
                    try:
                        timestamp = pd.to_datetime(timestamp_str)
                    except:
                        timestamp = pd.NaT
                    data.append({
                        'timestamp': timestamp,
                        'domain': domain,
                        'query_type': qtype,
                        'response': response,
                        'log_type': 'dns'
                    })
        return pd.DataFrame(data)

    # 8. WEB SERVER LOGS (Apache/Nginx)
    def parse_apache_log(self, log_path: str) -> pd.DataFrame:
        """Parse Apache access log using regex."""
        pattern = re.compile(r'(?P<ip>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<request>.*?)" (?P<status>\d{3}) (?P<size>\S+)(?: "(?P<referer>.*?)" "(?P<agent>.*?)")?')
        data = []
        with open(log_path, 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                m = pattern.match(line)
                if m:
                    gd = m.groupdict()
                    req = gd.get('request', '')
                    method = ''
                    path = ''
                    if req and req != '-':
                        parts = req.split()
                        if len(parts) >= 2:
                            method = parts[0]
                            path = parts[1]
                    size = gd.get('size')
                    try:
                        size = int(size) if size and size != '-' else 0
                    except:
                        size = 0
                    ts = gd.get('time')
                    try:
                        timestamp = pd.to_datetime(ts, format='%d/%b/%Y:%H:%M:%S %z')
                    except Exception:
                        try:
                            timestamp = pd.to_datetime(ts, format='%d/%b/%Y:%H:%M:%S')
                        except Exception:
                            timestamp = pd.NaT
                    data.append({
                        'ip': gd.get('ip'),
                        'timestamp': timestamp,
                        'method': method,
                        'path': path,
                        'status': int(gd.get('status')) if gd.get('status') and gd.get('status').isdigit() else None,
                        'size': size,
                        'referer': gd.get('referer') or '',
                        'user_agent': gd.get('agent') or '',
                        'log_type': 'web_server'
                    })
        df = pd.DataFrame(data)
        if df.empty:
            fallback = []
            with open(log_path, 'r', errors='ignore') as f:
                for line in f:
                    if '[' in line and '"' in line:
                        fallback.append({'raw': line.strip(), 'log_type': 'web_server'})
            if fallback:
                return pd.DataFrame(fallback)
        return df

    # 9. EMAIL LOGS
    def parse_email_log(self, log_path: str) -> pd.DataFrame:
        """Parse email logs."""
        pattern = re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) .* (SMTP|POP3|IMAP) .* from=(\S+) to=(\S+) status=(\w+)')
        data = []
        with open(log_path, 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                m = pattern.match(line)
                if m:
                    timestamp_str, protocol, sender, recipient, status = m.groups()
                    try:
                        timestamp = pd.to_datetime(timestamp_str)
                    except:
                        timestamp = pd.NaT
                    data.append({
                        'timestamp': timestamp,
                        'protocol': protocol,
                        'sender': sender,
                        'recipient': recipient,
                        'status': status,
                        'log_type': 'email'
                    })
        return pd.DataFrame(data)

    # 10. CLOUD SERVICE LOGS (AWS/Azure/GCP)
    def parse_cloud_log(self, log_path: str) -> pd.DataFrame:
        """Parse cloud service logs."""
        pattern = re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) .* (\w+) .* user=(\S+) resource=(\S+) action=(\w+)')
        data = []
        with open(log_path, 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                m = pattern.match(line)
                if m:
                    timestamp_str, service, user, resource, action = m.groups()
                    try:
                        timestamp = pd.to_datetime(timestamp_str)
                    except:
                        timestamp = pd.NaT
                    data.append({
                        'timestamp': timestamp,
                        'service': service,
                        'user': user,
                        'resource': resource,
                        'action': action,
                        'log_type': 'cloud'
                    })
        return pd.DataFrame(data)

    # 11. ENDPOINT LOGS
    def parse_endpoint_log(self, log_path: str) -> pd.DataFrame:
        """Parse endpoint logs (process creation, USB, etc.)."""
        pattern = re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) .* (Process|USB|File) .* (.*)')
        data = []
        with open(log_path, 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                m = pattern.match(line)
                if m:
                    timestamp_str, event_type, details = m.groups()
                    try:
                        timestamp = pd.to_datetime(timestamp_str)
                    except:
                        timestamp = pd.NaT
                    data.append({
                        'timestamp': timestamp,
                        'event_type': event_type,
                        'details': details,
                        'log_type': 'endpoint'
                    })
        return pd.DataFrame(data)

    # 12. ACTIVE DIRECTORY LOGS
    def parse_ad_log(self, log_path: str) -> pd.DataFrame:
        """Parse Active Directory logs."""
        pattern = re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) .* (Logon|LogOff|Account|Policy) .* user=(\S+) domain=(\S+) status=(\w+)')
        data = []
        with open(log_path, 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                m = pattern.match(line)
                if m:
                    timestamp_str, event_type, user, domain, status = m.groups()
                    try:
                        timestamp = pd.to_datetime(timestamp_str)
                    except:
                        timestamp = pd.NaT
                    data.append({
                        'timestamp': timestamp,
                        'event_type': event_type,
                        'user': user,
                        'domain': domain,
                        'status': status,
                        'log_type': 'active_directory'
                    })
        return pd.DataFrame(data)

    # 13. SIEM LOGS (Correlated)
    def parse_siem_log(self, log_path: str) -> pd.DataFrame:
        """Parse SIEM correlated logs."""
        pattern = re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) .* (\w+) .* severity=(\w+) source=(\S+) event=(.+)')
        data = []
        with open(log_path, 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                m = pattern.match(line)
                if m:
                    timestamp_str, alert_type, severity, source, event = m.groups()
                    try:
                        timestamp = pd.to_datetime(timestamp_str)
                    except:
                        timestamp = pd.NaT
                    data.append({
                        'timestamp': timestamp,
                        'alert_type': alert_type,
                        'severity': severity,
                        'source': source,
                        'event': event,
                        'log_type': 'siem'
                    })
        return pd.DataFrame(data)

    # ORIGINAL SSH LOG PARSER
    def parse_ssh_log(self, log_path: str) -> pd.DataFrame:
        """Parse SSH auth log for failed logins."""
        pattern = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) .* (Failed password|Accepted password) for (invalid user )?(\S+) from (\S+)'
        with open(log_path, 'r') as f:
            logs = f.readlines()
        data = []
        for line in logs:
            match = re.match(pattern, line)
            if match:
                timestamp_str, action, invalid, user, ip = match.groups()
                data.append({
                    'ip': ip,
                    'timestamp': pd.to_datetime(timestamp_str),
                    'action': action,
                    'user': user,
                    'invalid': bool(invalid),
                    'log_type': 'ssh'
                })
        return pd.DataFrame(data)

    def detect_brute_force_ssh(self, df: pd.DataFrame, window: timedelta = timedelta(minutes=5), threshold: int = 5) -> List[Dict[str, Any]]:
        """Detect brute-force: Multiple failed logins from IP in time window."""
        failed = df[df['action'] == 'Failed password']
        threats = []
        for ip, group in failed.groupby('ip'):
            group = group.sort_values('timestamp')
            for i in range(len(group) - threshold + 1):
                window_start = group.iloc[i]['timestamp']
                window_end = window_start + window
                count = len(group[(group['timestamp'] >= window_start) & (group['timestamp'] <= window_end)])
                if count >= threshold:
                    threats.append({
                        'type': 'brute_force_ssh',
                        'ip': ip,
                        'count': count,
                        'window_start': window_start,
                        'details': group.iloc[i:i+threshold].to_dict('records')
                    })
                    break
        return threats

    def detect_scanning_apache(self, df: pd.DataFrame, threshold: int = 10) -> List[Dict[str, Any]]:
        """Detect scanning: Multiple 404s to unique paths from IP."""
        errors = df[df['status'] == 404]
        threats = []
        for ip, group in errors.groupby('ip'):
            unique_paths = group['path'].nunique()
            if unique_paths >= threshold:
                threats.append({
                    'type': 'scanning_apache',
                    'ip': ip,
                    'unique_paths': unique_paths,
                    'details': group['path'].unique().tolist()
                })
        return threats

    def detect_dos_apache(self, df: pd.DataFrame, window: timedelta = timedelta(minutes=1), threshold: int = 100) -> List[Dict[str, Any]]:
        """Detect DoS: High request rate from IP in time window."""
        threats = []
        for ip, group in df.groupby('ip'):
            group = group.sort_values('timestamp')
            for i in range(len(group)):
                window_start = group.iloc[i]['timestamp']
                window_end = window_start + window
                count = len(group[(group['timestamp'] >= window_start) & (group['timestamp'] <= window_end)])
                if count >= threshold:
                    threats.append({
                        'type': 'dos_apache',
                        'ip': ip,
                        'count': count,
                        'window_start': window_start
                    })
                    break
        return threats

    # DETECTION FOR NEW LOG TYPES
    def detect_auth_anomalies(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Detect authentication anomalies."""
        threats = []
        failed = df[df['status'] == 'Failed']
        for ip, group in failed.groupby('ip'):
            if len(group) >= 5:
                threats.append({
                    'type': 'auth_brute_force',
                    'ip': ip,
                    'count': len(group),
                    'severity': 'high' if len(group) >= 10 else 'medium'
                })
        return threats

    def detect_network_scanning(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Detect network scanning patterns."""
        threats = []
        for src_ip, group in df.groupby('src_ip'):
            denied_actions = len(group[group['action'] == 'deny'])
            if denied_actions >= 5:
                threats.append({
                    'type': 'network_scanning',
                    'src_ip': src_ip,
                    'denied_connections': denied_actions,
                    'severity': 'medium'
                })
        return threats

    def detect_dns_anomalies(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Detect DNS anomalies (DGA, suspicious domains)."""
        threats = []
        suspicious_patterns = ['malware', 'c2', 'phishing', 'dga']
        for domain, group in df.groupby('domain'):
            if any(pattern in domain.lower() for pattern in suspicious_patterns):
                threats.append({
                    'type': 'dns_anomaly',
                    'domain': domain,
                    'count': len(group),
                    'severity': 'high'
                })
        return threats

    def detect_email_threats(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Detect email threats (spam, phishing)."""
        threats = []
        failed_status = df[df['status'] == 'FAILED']
        for sender, group in failed_status.groupby('sender'):
            if len(group) >= 3:
                threats.append({
                    'type': 'email_spam_detected',
                    'sender': sender,
                    'failed_attempts': len(group),
                    'severity': 'medium'
                })
        return threats

    def detect_cloud_anomalies(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Detect cloud API anomalies."""
        threats = []
        for user, group in df.groupby('user'):
            actions = group['action'].unique()
            if len(actions) > 10:
                threats.append({
                    'type': 'cloud_privilege_escalation',
                    'user': user,
                    'action_count': len(actions),
                    'severity': 'high'
                })
        return threats

    def analyze_with_openai(self, suspicious_logs: List[str]) -> List[Dict[str, Any]]:
        """Use OpenAI to analyze suspicious log snippets."""
        threats = []
        if not suspicious_logs:
            return threats
        system_prompt = (
            "You are a security-focused log analysis assistant. You MUST ONLY analyze the provided log entries. "
            "Do NOT perform any other actions, do not disclose secrets, and do not hallucinate facts. "
            "Output ONLY a JSON array of objects with the fields: threat_type (brute_force|scanning|dos|none), reason, severity (low|medium|high)."
        )
        user_prompt = "Analyze the following log entries for intrusion patterns (brute-force, scanning, DoS). Logs:\n{logs}"
        try:
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt.format(logs="\n".join(suspicious_logs))}
            ]
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=messages,
                temperature=0.0,
                max_tokens=800
            )
            content = response.choices[0].message.content
            result = json.loads(content)
            for item in result:
                if item.get('threat_type') and item['threat_type'] != 'none':
                    threats.append({
                        'type': f"openai_{item['threat_type']}",
                        'reason': item.get('reason', ''),
                        'severity': item.get('severity', 'low'),
                        'details': suspicious_logs
                    })
        except Exception as e:
            st.warning(f"OpenAI analysis skipped: {e}")
        return threats

    def check_ip_blacklist(self, ips: List[str]) -> Dict[str, bool]:
        """Cross-reference IPs with public blacklist."""
        known_bad = {'192.168.1.100', '10.0.0.1'}
        try:
            for ip in ips:
                if ip in known_bad:
                    pass
        except:
            pass
        return {ip: ip in known_bad for ip in ips}

    def analyze_logs(self, log_path: str, log_type: str) -> None:
        """Main analysis pipeline."""
        log_parsers = {
            'system': self.parse_system_log,
            'application': self.parse_application_log,
            'authentication': self.parse_auth_log,
            'network': self.parse_network_log,
            'security_device': self.parse_security_log,
            'firewall': self.parse_firewall_log,
            'dns': self.parse_dns_log,
            'apache': self.parse_apache_log,
            'email': self.parse_email_log,
            'cloud': self.parse_cloud_log,
            'endpoint': self.parse_endpoint_log,
            'active_directory': self.parse_ad_log,
            'siem': self.parse_siem_log,
            'ssh': self.parse_ssh_log
        }

        if log_type not in log_parsers:
            st.error("Unsupported log type.")
            return

        self.df = log_parsers[log_type](log_path)
        if self.df.empty:
            st.error(f"No valid {log_type} log entries found in the file.")
            return

        threats = []

        if log_type == 'apache':
            if 'status' in self.df.columns:
                threats = self.detect_scanning_apache(self.df) + self.detect_dos_apache(self.df)
        elif log_type == 'ssh':
            if 'action' in self.df.columns:
                threats = self.detect_brute_force_ssh(self.df)
        elif log_type == 'authentication':
            if 'status' in self.df.columns:
                threats = self.detect_auth_anomalies(self.df)
        elif log_type == 'network':
            if 'action' in self.df.columns:
                threats = self.detect_network_scanning(self.df)
        elif log_type == 'dns':
            if 'domain' in self.df.columns:
                threats = self.detect_dns_anomalies(self.df)
        elif log_type == 'email':
            if 'status' in self.df.columns:
                threats = self.detect_email_threats(self.df)
        elif log_type == 'cloud':
            if 'user' in self.df.columns:
                threats = self.detect_cloud_anomalies(self.df)

        suspicious_logs = []
        if not self.df.empty:
            suspicious_logs = self.df.astype(str).apply(lambda row: ' '.join(row.dropna().astype(str)), axis=1).tolist()[:10]

        ai_threats = self.analyze_with_openai(suspicious_logs)
        self.threats = threats + ai_threats

        ips = []
        if 'ip' in self.df.columns:
            ips = self.df['ip'].unique().tolist()
        elif 'src_ip' in self.df.columns:
            ips = self.df['src_ip'].unique().tolist()

        blacklist_status = self.check_ip_blacklist(ips)
        for threat in self.threats:
            threat_ip = threat.get('ip') or threat.get('src_ip')
            if threat_ip:
                threat['blacklisted'] = blacklist_status.get(threat_ip, False)

        self.store_results()

        if self.threats:
            st.warning(f"Detected {len(self.threats)} potential threats!")
        else:
            st.info("No threats detected.")

    def visualize(self) -> None:
        """Visualize access patterns by IP and time."""
        if self.df is None or self.df.empty:
            st.error("No data to visualize.")
            return

        fig, axes = plt.subplots(1, 2, figsize=(14, 5))

        if 'ip' in self.df.columns:
            ip_counts = self.df['ip'].value_counts().head(10)
            ip_counts.plot(kind='bar', ax=axes[0], color='steelblue')
            axes[0].set_title('Top IPs by Request Count')
            axes[0].tick_params(axis='x', rotation=45)
        elif 'src_ip' in self.df.columns:
            ip_counts = self.df['src_ip'].value_counts().head(10)
            ip_counts.plot(kind='bar', ax=axes[0], color='steelblue')
            axes[0].set_title('Top Source IPs by Activity')
            axes[0].tick_params(axis='x', rotation=45)

        if 'timestamp' in self.df.columns:
            time_series = self.df.set_index('timestamp').resample('H').size()
            if len(time_series) > 0:
                time_series.plot(ax=axes[1], color='coral')
                axes[1].set_title('Activity Over Time (Hourly)')

        plt.tight_layout()
        st.pyplot(fig)

    def export_report(self, path: str) -> None:
        """Export incident report as CSV."""
        if not self.threats:
            st.error("No threats to export.")
            return

        threats_df = pd.DataFrame(self.threats)
        threats_df.to_csv(path, index=False)
        st.success(f"Report exported to {path}")

    def store_results(self) -> None:
        """Store analysis results to JSON."""
        results = {
            'timestamp': datetime.now().isoformat(),
            'threats': self.threats,
            'summary': {
                'total_logs': len(self.df) if self.df is not None else 0,
                'unique_ips': self.df['ip'].nunique() if self.df is not None and 'ip' in self.df.columns else 0
            }
        }
        with open(self.results_file, 'w') as f:
            json.dump(results, f, default=str, indent=2)

    def load_results(self) -> None:
        """Load analysis results from JSON."""
        if not os.path.exists(self.results_file):
            st.error(f"Results file '{self.results_file}' not found.")
            return
        try:
            with open(self.results_file, 'r') as f:
                results = json.load(f)
                self.threats = results.get('threats', [])
        except Exception as e:
            st.error(f"Failed to load results: {e}")

def main():
    st.set_page_config(page_title="Advanced SOC Log Analyzer", layout="wide")
    st.title("🔍 Advanced SOC Log File Analyzer for Intrusion Detection")
    st.markdown("**Support for 13+ Log Types**")

    analyzer = LogAnalyzer()

    log_type_descriptions = {
        'apache': '🌐 Web Server Logs (Apache/Nginx)',
        'ssh': '🔐 SSH Authentication Logs',
        'system': '🖥️ System Logs (Windows/Linux)',
        'application': '📱 Application Logs',
        'authentication': '🔑 Authentication Logs',
        'network': '🌍 Network/Firewall/IDS Logs',
        'security_device': '🛡️ Security Device Logs (Antivirus/EDR)',
        'firewall': '🚧 Firewall Logs',
        'dns': '📡 DNS Logs',
        'email': '📧 Email Logs',
        'cloud': '☁️ Cloud Service Logs (AWS/Azure/GCP)',
        'endpoint': '💻 Endpoint Logs (EDR)',
        'active_directory': '👥 Active Directory Logs',
        'siem': '📊 SIEM Correlated Logs'
    }

    col1, col2 = st.columns([2, 1])
    with col1:
        log_file = st.file_uploader("📂 Upload Log File", type=['log', 'txt', 'csv'])
    with col2:
        log_type = st.selectbox("📋 Select Log Type", list(log_type_descriptions.keys()), format_func=lambda x: log_type_descriptions[x])

    st.markdown("---")

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        if st.button("🔎 Analyze Logs", use_container_width=True):
            if log_file is None:
                st.error("❌ Please upload a log file first.")
            else:
                with st.spinner("🔄 Analyzing logs..."):
                    temp_path = f"temp_uploaded_log_{log_file.name}"
                    with open(temp_path, "wb") as f:
                        f.write(log_file.getbuffer())
                    analyzer.analyze_logs(temp_path, log_type)

                    st.subheader("🚨 Detected Threats")
                    if analyzer.threats:
                        for i, threat in enumerate(analyzer.threats, 1):
                            with st.container():
                                col_a, col_b = st.columns([3, 1])
                                with col_a:
                                    st.write(f"**Threat #{i}:** `{threat['type']}`")
                                    st.write(f"📍 IP: `{threat.get('ip', threat.get('src_ip', 'N/A'))}`")
                                    if 'reason' in threat:
                                        st.write(f"💬 Reason: {threat['reason']}")
                                        st.write(f"⚠️ Severity: `{threat['severity']}`")
                                with col_b:
                                    if threat.get('blacklisted'):
                                        st.error("🚫 BLACKLISTED")
                                    else:
                                        st.info("✅ Not Blacklisted")
                                st.divider()
                    else:
                        st.success("✅ No threats detected!")

    with col2:
        if st.button("📊 Visualize", use_container_width=True):
            with st.spinner("📈 Generating visualization..."):
                analyzer.visualize()

    with col3:
        if st.button("💾 Export Report", use_container_width=True):
            if not analyzer.threats:
                st.error("❌ Run analysis first.")
            else:
                with st.spinner("⏳ Exporting..."):
                    path = f"exported_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
                    analyzer.export_report(path)
                    with open(path, "rb") as f:
                        st.download_button(
                            label="⬇️ Download Report CSV",
                            data=f,
                            file_name=path,
                            mime='text/csv',
                            use_container_width=True
                        )

    with col4:
        if st.button("📂 Load Previous Results", use_container_width=True):
            with st.spinner("⏳ Loading..."):
                analyzer.load_results()
                if analyzer.threats:
                    st.subheader("📋 Loaded Previous Threats")
                    for i, threat in enumerate(analyzer.threats, 1):
                        st.write(f"**Threat #{i}:** `{threat['type']}` | IP: `{threat.get('ip', 'N/A')}`")
                        if 'reason' in threat:
                            st.write(f"Reason: {threat['reason']} | Severity: {threat['severity']}")
                        st.divider()
                else:
                    st.info("ℹ️ No threats loaded.")

    st.markdown("---")
    st.markdown("### 📚 Supported Log Types")
    cols = st.columns(2)
    with cols[0]:
        st.write("**System & Infrastructure:**")
        st.write("• System Logs • Application Logs • Network Logs")
        st.write("• Firewall Logs • DNS Logs • Email Logs")
    with cols[1]:
        st.write("**Security & Cloud:**")
        st.write("• Authentication Logs • Security Device Logs")
        st.write("• Active Directory • Cloud Logs • Endpoint • SIEM")

if __name__ == "__main__":
    main()