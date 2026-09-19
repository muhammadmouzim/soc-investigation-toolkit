# SOC Investigation Toolkit

A Python-based cybersecurity project designed to practice basic Security Operations Center (SOC) investigation tasks, threat intelligence, log analysis, and Indicator of Compromise (IOC) extraction.

The toolkit combines several small investigation modules into one practical project that demonstrates how common security data such as IP addresses, file hashes, URLs, authentication logs, and IOCs can be analyzed during a basic SOC investigation.

---

## Project Overview

Security analysts often need to investigate different types of security information during an investigation.

This project provides a lightweight command-line toolkit for performing several common investigation tasks:

* IP address investigation
* File hash identification and calculation
* VirusTotal threat intelligence
* URL analysis
* DNS resolution
* Authentication log analysis
* IOC extraction

The project was developed as part of my cybersecurity learning journey to strengthen practical skills in Python, threat intelligence, log analysis, and SOC investigation workflows.

---

## Features

### 1. IP Investigation

The IP Investigation module:

* Validates IPv4 and IPv6 addresses
* Identifies private, public, loopback, and reserved addresses
* Retrieves basic public IP intelligence
* Displays country, region, city, organization, and ASN information when available
* Uses an external IP intelligence API
* Includes fallback handling when the primary service is unavailable or rate limited

---

### 2. Hash Investigation

The Hash Investigation module supports:

* MD5 identification
* SHA-1 identification
* SHA-256 identification
* SHA-512 identification
* File hashing
* File size information
* VirusTotal threat intelligence
* Basic SOC assessment

The module can either investigate an existing hash or calculate multiple hashes from a local file.

---

### 3. URL Investigation

The URL Investigation module performs:

* URL validation
* URL normalization
* Scheme identification
* Domain analysis
* Port identification
* Path analysis
* Query and fragment detection
* IP address detection
* DNS resolution
* Suspicious indicator detection
* VirusTotal URL intelligence
* Basic SOC assessment

The module checks for indicators such as:

* HTTP instead of HTTPS
* IP addresses used instead of domain names
* Suspicious URL keywords
* Excessively long URLs
* `@` symbols
* Multiple domain components
* Punycode domains

These checks are heuristic indicators and do not independently prove that a URL is malicious.

---

### 4. Authentication Log Analysis

The Log Parser module analyzes authentication logs and identifies:

* Successful login attempts
* Failed login attempts
* Users associated with failed logins
* Source IP addresses
* Repeated failed login activity
* Account lock events
* Suspicious authentication events

The module provides a basic SOC-style assessment when repeated failed login activity is detected.

---

### 5. IOC Extraction

The IOC Extractor module extracts common Indicators of Compromise from security-related text.

It supports:

* IPv4 addresses
* URLs
* Domains
* MD5 hashes
* SHA-1 hashes
* SHA-256 hashes
* SHA-512 hashes

The module removes duplicates and provides a summary of extracted indicators.

---

## SOC Investigation Workflow

The toolkit follows a simplified SOC investigation workflow:

```text
Security Data
     |
     v
Identify Indicator
     |
     v
Validate Input
     |
     v
Collect Intelligence
     |
     v
Analyze Evidence
     |
     v
Identify Suspicious Activity
     |
     v
SOC Assessment
     |
     v
Further Investigation / Response
```

The toolkit is intended for educational investigation and does not replace a complete enterprise SOC platform.

---

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
├── test.txt
├── test_virusTotal.py
├── requirements.txt
├── README.md
├── .gitignore
├── .env
└── venv/
```

### Important

The `.env` file contains local API credentials and must not be committed to GitHub.

The actual `.env` file is protected by `.gitignore`.

---

## Technologies Used

### Programming Language

* Python 3

### Python Libraries

* `requests`
* `python-dotenv`
* `re`
* `hashlib`
* `socket`
* `ipaddress`
* `base64`
* `urllib.parse`
* `collections.Counter`

### External Services

* VirusTotal
* IP intelligence API services

### Development Environment

* Visual Studio Code
* Kali Linux
* Windows
* Git
* GitHub
* PowerShell
* Linux Terminal

---

## Installation and Setup

### 1. Clone the repository

```bash
git clone https://github.com/muhammadmouzim/soc-investigation-toolkit.git
```

Move into the project:

```bash
cd soc-investigation-toolkit
```

---

### 2. Create a virtual environment

```bash
python3 -m venv venv
```

Activate it:

```bash
source venv/bin/activate
```

On Windows PowerShell:

```powershell
.\venv\Scripts\Activate.ps1
```

---

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

---

### 4. Configure VirusTotal

Create a local `.env` file:

```text
VT_API_KEY=YOUR_VIRUSTOTAL_API_KEY
```

Never publish the actual API key.

---

## Requirements

The project requires:

```text
requests
python-dotenv
```

These dependencies are listed in `requirements.txt`.

## How to Run

## IP Investigation

```bash
python3 1.ip_lookup.py
```

Enter an IP address when prompted.

Example:

```text
8.8.8.8
```

---

## Hash Investigation

```bash
python3 2.hash_checker.py
```

Choose:

```text
1
```

to investigate an existing hash.

Or choose:

```text
2
```

to calculate hashes from a local file.

---

## URL Investigation

```bash
python3 3.url_analyzer.py
```

Example:

```text
example.com
```

---

## Authentication Log Analysis

```bash
python3 4.log_parser.py
```

The module analyzes the configured sample authentication log.

---

## IOC Extraction

```bash
python3 5.ioc_extractor.py
```

Paste security-related text and press Enter on an empty line when finished.

Example:

```text
Suspicious login from 203.0.113.50
URL: http://evil-example.com/login
Hash: 44d88612fea8a8f36de82e1278abb02f
```

---

## Testing and Results

The project was tested using controlled and educational test data.

## Hash investigation

The VirusTotal integration was tested using the EICAR antivirus test hash.

The toolkit successfully:

* Identified the hash as MD5
* Submitted the hash to VirusTotal
* Retrieved threat intelligence results
* Displayed malicious, suspicious, harmless, and undetected counts
* Generated a basic SOC assessment

VirusTotal detection counts can change over time as security vendors update their analysis.

---

## URL investigation

The URL Analyzer was tested using:

```text
example.com
```

The toolkit successfully:

* Normalized the URL
* Identified HTTPS
* Resolved DNS addresses
* Checked suspicious indicators
* Queried VirusTotal
* Produced a final SOC assessment

A controlled suspicious example was also tested using:

```text
http://192.0.2.1/login
```

The toolkit identified indicators including:

* HTTP instead of HTTPS
* IP address used instead of a domain
* Login-related keyword

---

## Authentication log Analysis

The sample authentication log contains controlled test events.

The toolkit detected repeated failed login activity, including:

```text
203.0.113.50 → 5 failed login attempts
198.51.100.25 → 3 failed login attempts
```

It also detected an account-lock event associated with the test activity.

The addresses used in the sample log belong to documentation/test address ranges and are used only as controlled demonstration data.

---

## IOC extraction

The IOC Extractor was tested with controlled security-related text containing:

* IP addresses
* URLs
* Domains
* File hashes

The toolkit successfully extracted and categorized the supported IOC types.

---

## VirusTotal Integration

VirusTotal is used as an external threat intelligence source for:

* File hash lookups
* URL analysis

The project uses the VirusTotal API to retrieve available analysis statistics.

VirusTotal results should be treated as **threat intelligence evidence**, not as the sole basis for declaring an object malicious or safe.

A hash not found in VirusTotal does not automatically mean that a file is safe.

---

## Security Considerations

## API Key Protection

The VirusTotal API key is stored in `.env` rather than directly inside Python source code.

The `.env` file is excluded from Git using:

```text
.env
```

in `.gitignore`.

### Safe Testing

The project uses controlled and educational test data.

The EICAR test hash is used for safe antivirus/ threat-intelligence testing instead of real malware.

### External APIs

External intelligence services may:

* Rate limit requests
* Change detection results
* Become temporarily unavailable
* Provide incomplete information

The toolkit handles common API failures where applicable.

---

## Limitations

This project is designed for educational and portfolio purposes.

Current limitations include:

* It is a command-line toolkit rather than a complete SOC platform.
* It does not provide real-time monitoring.
* It does not replace a SIEM.
* It does not replace an EDR solution.
* URL detection uses basic heuristic indicators.
* Log analysis uses a simplified log format.
* External API availability can affect results.
* VirusTotal results may change over time.
* IP geolocation information is approximate.
* The toolkit does not automatically contain or remediate security incidents.

---

## Future Improvements

Possible future improvements include:

* Graphical User Interface
* More log formats
* Windows Event Log support
* Linux authentication log support
* Additional IOC types
* Threat intelligence integrations
* Automated report generation
* JSON and CSV export
* SIEM integration
* MITRE ATT&CK mapping
* IOC reputation scoring
* Investigation history
* Improved detection rules
* Automated case management

---

## Learning Outcomes

Through this project, I practiced:

* Python programming
* Python modules and functions
* Regular expressions
* Cryptographic hashing
* API integration
* Environment variable management
* DNS resolution
* URL parsing
* Log analysis
* Threat intelligence
* IOC extraction
* Basic SOC investigation
* Git and GitHub
* Security-focused documentation

The project also helped connect theoretical SOC concepts with practical investigation tasks.

---

## Project Purpose

The main purpose of this project is to build practical cybersecurity skills through hands-on implementation.

The toolkit demonstrates how different security data sources can be analyzed together during a simplified SOC investigation.

It was developed as part of my continued cybersecurity learning journey, with a focus on SOC operations, threat detection, threat intelligence, and Blue Team skills.

---

## GitHub Repository

Repository:

<https://github.com/muhammadmouzim/soc-investigation-toolkit>

The repository contains the project source code, sample data, documentation, and configuration files required to understand the project.

---

## Copyright

Copyright © 2026 Muhammad Mouzim Fiaz.

This project and its documentation are provided for educational and portfolio purposes.

The repository is publicly available for viewing and evaluation. No permission is granted to copy, modify, redistribute, or present this work as your own without permission from the author.

Third-party libraries, APIs, services, and external resources used by this project remain the property of their respective owners.

---

## Disclaimer

This project is intended for **educational, defensive cybersecurity, and portfolio purposes only**.

The tools and techniques demonstrated in this repository should only be used on systems, data, accounts, and resources for which you have authorization.

The author is not responsible for misuse of this project or for any damage resulting from unauthorized use.

External services such as VirusTotal and IP intelligence providers are subject to their own terms, policies, limitations, and availability.

---

## Author

***Muhammad Mouzim Fiaz**

Cybersecurity Student
Interested in SOC Operations, Blue Team, Threat Detection, Incident Response, Threat Intelligence, and Digital Forensics.
