# Log-analyzer
This project serves as a foundational intrusion detection tool and can be expanded into a full SIEM-like component

	           INTERNSHIP REPORT
Name: CHUDARAJ KUSHWAHA

<img width="1920" height="1013" alt="image" src="https://github.com/user-attachments/assets/ccb0f831-ff4b-41f4-87b4-38beb93248ad" />

###
Log File Analyzer for Intrusion Detection Report
1. Introduction
Modern digital infrastructures continuously generate log data from multiple sources such as web servers, authentication services, and system daemons. These logs contain valuable information about user activities, system behavior, and potential security threats. As cyberattacks such as brute-force attempts, port scanning, and denial-of-service (DoS) attacks continue to rise, organizations require efficient mechanisms to analyze logs and detect suspicious behavior in real time.
This project aims to design and develop a Log File Analyzer for Intrusion Detection using Python, Regular Expressions (regex), Pandas, and Matplotlib. The tool focuses on parsing logs, identifying attack patterns, visualizing traffic trends, and generating detailed incident reports. The analyzer is intended to support security teams in early threat detection and response.

### 2. Objectives
The primary objective of this project is to build an automated system capable of detecting suspicious log patterns across different log types. The tool is designed to:
    1. Parse Apache, SSH, and system logs efficiently.
    2. Identify common attack patterns, including:
        ◦ Brute-force login attempts
        ◦ Port scanning activities
        ◦ Distributed Denial-of-Service (DDoS) surges
    3. Visualize access patterns to highlight abnormal spikes and malicious IP behavior.
    4. Export incident reports summarizing suspicious events for SOC review.

### 3. Tools and Technologies
Python
Provides a flexible environment for text processing, data analysis, and automation.
Pandas
Enables data cleaning, transformation, filtering, grouping, and anomaly detection based on frequency and patterns.
Matplotlib
Used to visualize trends such as hourly spikes, failed auth attempts, and IP distribution.

### 4. Methodology
4.1 Log Parsing
The tool begins by ingesting raw log files from Apache (access.log) and SSH (auth.log).
Regex patterns are used to extract structured fields:
    • Apache fields: IP, timestamp, method, URL, status code, bytes sent
    • SSH fields: login attempts, authentication success/failure, usernames, source IPs
Data is converted into a Pandas DataFrame for efficient analysis.

4.2 Threat Pattern Detection
a. Brute-force attacks
    • Multiple failed SSH logins from the same IP
    • Sudden increase in 401/403 responses from Apache
Detectionlogic:
IP with > X failed attempts in < 5 minutes → Suspicious

b. Port Scanning
Identified by sequential access to multiple endpoints or services within a short time.
Example indicators:
    • Apache: numerous 404/400 responses
    • SSH: repeated connection attempts

c. DoS / DDoS Patterns
Abnormally high request volume from a single IP or multiple IPs over a short duration.
Detection logic:
Requests/minute from IP > threshold
Visualized using plots.

4.3 IP Reputation Checking
The tool queries publicly available threat feeds such as:
    • AbuseIPDB
    • VirusTotal
    • OTX (AlienVault)
    • Spamhaus DROP list
Suspicious IPs are tagged with reputation scores and threat categories.

4.4 Incident Report Generation
For each detected event, the tool exports:
    • Timestamp
    • IP address
    • Attack type
    • Log snippet
    • Risk classification
    • Recommended mitigation
The report is saved in CSV/JSON/PDF format (as needed).

### 5. Results and Findings
During testing with mixed log datasets:
    • Multiple brute-force attempts from repeated IPs were successfully detected.
    • High-frequency request bursts were correctly marked as potential DoS activity.
    • Visualization clearly displayed abnormal spikes compared to baseline traffic.
    • Cross-referencing revealed several IPs already listed in global blacklists.
The project demonstrates that automated log analysis significantly improves detection efficiency and reduces manual review workload.

### Conclusion
The Log File Analyzer for Intrusion Detection effectively identifies various suspicious patterns using a combination of Python, regex, Pandas, and Matplotlib.
Future improvements may include:
    • Real-time monitoring with WebSockets/Flask
    • Machine learning for behavioral anomaly detection
    • Streamlit dashboard with threat heatmaps
This project serves as a foundational intrusion detection tool and can be expanded into a full SIEM-like component.
