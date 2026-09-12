Integrated Threat Intelligence, SOC Monitoring & Vulnerability Assessment Using Honeypot-Based Attack Simulation

A hands-on cybersecurity project combining honeypot-based threat intelligence collection, cloud-native SOC monitoring, and vulnerability assessment/penetration testing (VAPT) — built end-to-end across local and AWS cloud environments.

Overview : 
This project implements a complete cybersecurity attack-detection lifecycle:

Deployed a Cowrie honeypot — both locally (Docker, controlled simulation) and on a public AWS EC2 instance (real, unsolicited internet attackers)
Analyzed captured attack data using a custom Python pipeline and a Splunk SIEM
Validated real-world exploitability by reproducing a critical CVE (Log4Shell) and attacking a deliberately vulnerable API (VAmPI) across the OWASP API Security Top 10
Configured AWS-native SOC monitoring services (CloudTrail, VPC Flow Logs, GuardDuty, Security Hub) for account and network-level visibility

Key Findings : 
Within ~24 hours of public exposure, the AWS honeypot captured connection attempts from 12+ unique, unsolicited internet source IPs, including 2 genuine successful unauthorized logins using leaked/weak credentials
Successfully reproduced and exploited CVE-2021-44228 (Log4Shell), confirmed via an outbound JNDI/LDAP callback to a controlled listener
Identified and exploited 5 vulnerabilities on VAmPI spanning the OWASP API Security Top 10: Excessive Data Exposure, Broken Object Level Authorization (BOLA), SQL Injection, Mass Assignment, and Lack of Rate Limiting
AWS GuardDuty independently flagged a real cloud security posture finding (root account credential misuse)
Built a working Splunk SIEM with cross-source dashboards and a scheduled automated detection alert

Tools & Technologies : 
Category	                       Tools
Honeypot	                       Cowrie (SSH/Telnet emulation)
Containerization	               Docker
Cloud Platform	                 AWS EC2, VPC, CloudTrail, VPC Flow Logs, GuardDuty, Security Hub
Attacker Toolkit	               Kali Linux (via WSL2)
Reconnaissance & Brute-Force	   Nmap, Hydra
VAPT Targets	                   Vulhub (Apache Solr / Log4j), VAmPI (vulnerable REST API)
Exploitation	                   Custom JNDI/LDAP payloads, curl, sqlmap
Data Analysis	                   Python (JSON parsing, Matplotlib visualization)
SIEM	                           Splunk Enterprise

Methodology : 
Deployed Cowrie honeypot locally and simulated attacker behavior (manual logins, Hydra brute-force, post-login commands)
Deployed an identical Cowrie honeypot on a public AWS EC2 instance and passively monitored for genuine internet attack traffic
Built a Python analysis pipeline to extract statistics (top credentials, commands, connection timeline) from both datasets
Deployed Vulhub's vulnerable Apache Solr/Log4j environment and reproduced CVE-2021-44228 via a crafted JNDI/LDAP payload, confirmed through an out-of-band listener callback
Deployed VAmPI on a second AWS EC2 instance and performed five distinct attacks mapped to the OWASP API Security Top 10
Configured a custom AWS VPC, CloudTrail, VPC Flow Logs, GuardDuty, and Security Hub for account/network-level monitoring
Installed Splunk Enterprise locally, ingested honeypot and VAmPI log data, built cross-source dashboards, and configured a scheduled detection alert

Recommendations : 
Enforce strong, unique credentials and multi-factor authentication on all internet-facing services
Maintain rigorous patch management — Log4Shell remained exploitable in unpatched systems long after a fix was available
Apply object-level authorization checks on every API endpoint to prevent BOLA
Use parameterized queries to eliminate SQL injection risk
Implement rate limiting on authentication endpoints
Centralize logging and alerting (SIEM) to reduce detection time for real-world attacks

Author : 
Likhitha Panneeru

References : 
Cowrie Honeypot
Vulhub
VAmPI
CVE-2021-44228 — NVD
OWASP API Security Top 10
