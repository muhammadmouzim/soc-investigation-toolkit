\# SOC Investigation Toolkit

A practical Python-based toolkit for basic Security Operations Center (SOC) investigation tasks.

This project was developed as a cybersecurity learning project to practice IP investigation, file hash analysis, URL investigation, authentication log analysis, and Indicator of Compromise (IOC) extraction.


The toolkit combines local analysis with threat intelligence APIs to simulate common investigation tasks performed during SOC alert triage.


\## Features


\### 1. IP Investigation

\- Validates IPv4 and IPv6 addresses.

\- Identifies private and public IP addresses.

\- Retrieves basic public IP intelligence.

\- Displays country, region, city, organization, and ASN information.


\### 2. Hash Investigation

\- Identifies MD5, SHA-1, SHA-256, and SHA-512 hashes.

\- Calculates multiple cryptographic hashes from files.

\- Checks file hashes against VirusTotal.

\- Displays malicious, suspicious, harmless, and undetected results.

\- Provides a basic SOC assessment.



\### 3. URL Investigation

\- Validates HTTP and HTTPS URLs.

\- Analyzes URL components such as domain, path, query, and port.

\- Resolves domains to IP addresses.

\- Detects basic suspicious URL characteristics.

\- Checks URLs using VirusTotal threat intelligence.

\- Provides a final SOC assessment.



\### 4. Authentication Log Analysis

\- Parses authentication log entries.

\- Counts failed and successful login attempts.

\- Identifies repeated failed login activity.

\- Detects account-lock events.

\- Highlights IP addresses requiring investigation.

\- Produces a basic SOC priority assessment.



\### 5. IOC Extraction

\- Extracts IP addresses from security data.

\- Extracts URLs and domains.

\- Identifies MD5, SHA-1, SHA-256, and SHA-512 hashes.

\- Removes duplicate indicators.

\- Provides an IOC summary.



\## SOC Investigation Workflow



The toolkit demonstrates a simplified SOC investigation workflow:



```text

Security Alert / Log Data

&#x20;         ↓

&#x20;    IOC Extraction

&#x20;         ↓

&#x20;  IOC Investigation

&#x20;    ↙      ↓      ↘

&#x20;   IP     Hash     URL

&#x20;         ↓

&#x20;  Threat Intelligence

&#x20;         ↓

&#x20;    Log Analysis

&#x20;         ↓

&#x20;   SOC Assessment


## Project Structure

```text
soc-investigation-toolkit/
│
├── 1.ip_lookup.py
├── 2.hash_checker.py
├── 3.url_analyzer.py
├── 4.log_parser.py
├── 5.ioc_extractor.py
│
├── sample_data/
│   └── auth.log
│
├── test_virusTotal.py
├── test.txt
├── requirements.txt
├── .env
├── .gitignore
└── README.md




