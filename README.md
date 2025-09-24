# RISE
Reconnaissance Intelligence &amp; Synthesis Engine (under development)

A simple recon tool I'm making, the tool is in its beginning phase, yet to add many features.

A modular and concurrent reconnaissance tool designed for security professionals and penetration testers to efficiently gather intelligence about target domains.

## Features

- **DNS Enumeration**: Comprehensive DNS record discovery (A, AAAA, MX, NS, TXT, SOA, CNAME)
- **Subdomain Discovery**: Concurrent subdomain brute-forcing with customizable wordlists
- **Port Scanning**: Fast TCP port scanning with common and extended port ranges
- **Web Technology Detection**: Identifies web technologies, security headers, and common files
- **Concurrent Processing**: Multi-threaded execution for improved performance
- **Flexible Reporting**: Generate reports in TXT, JSON, and HTML formats
- **Configuration Management**: Customizable settings via JSON configuration file
- **Interactive & Non-Interactive Modes**: Suitable for both manual testing and automation

## Installation

### Requirements

- Python 3.8 or newer
- Required Python packages:
  - `requests`
  - `dnspython`

### Installation Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/rise.git
   cd rise
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Make the script executable (optional):
   ```bash
   chmod +x rise.py
   ```

## Usage

### Interactive Mode

Run the script without any arguments to enter interactive mode:

```bash
python rise.py
```

Follow the on-screen menu to select scanning options:

```
██████╗ ██╗███████╗███████╗
██╔══██╗██║██╔════╝██╔════╝
██████╔╝██║███████╗█████╗
██╔══██╗██║╚════██║██╔══╝
██║  ██║██║███████║███████╗
╚═╝  ╚═╝╚═╝╚══════╝╚══════╝
Reconnaissance Intelligence & Synthesis Engine v3.0

Enter target domain (e.g., example.com): example.com

============================================================
MENU
============================================================
  [1] DNS Enumeration
  [2] Subdomain Discovery
  [3] Port Scanning
  [4] Web Technology Detection
  [5] Run Full Reconnaissance (All Modules)
------------------------------------------------------------
  [6] Generate Report
  [7] Show Results Summary
  [0] Exit
============================================================
Enter your choice: 
```

### Non-Interactive Mode

For automation and scripting, use command-line arguments:

```bash
python rise.py <target> [options]
```

#### Options

- `-m, --module`: Specify which module to run (dns, subdomain, port, web, all)
- `--ports`: Port range for port scanning (common, extended) [default: common]
- `--format`: Report output format (txt, json, html, all) [default: all]
- `--no-interactive`: Run in non-interactive mode (requires target and module)

#### Examples

1. Run all modules against a target:
   ```bash
   python rise.py example.com --module all
   ```

2. Perform only DNS enumeration:
   ```bash
   python rise.py example.com --module dns
   ```

3. Run port scanning with extended ports:
   ```bash
   python rise.py example.com --module port --ports extended
   ```

4. Generate only JSON reports:
   ```bash
   python rise.py example.com --module all --format json
   ```

## Configuration

RISE uses a JSON configuration file (`rise_config.json`) for customizable settings. If the file doesn't exist, it will be created with default values on first run.

### Default Configuration

```json
{
    "output_dir": "./rise_results",
    "max_threads": 50,
    "timeout": 10,
    "log_level": "INFO",
    "wordlists": {
        "subdomains": [
            "www", "mail", "ftp", "admin", "test", "dev", "stage", "api",
            "blog", "shop", "support", "help", "docs", "cdn", "static",
            "img", "media", "news", "forum", "login", "secure", "beta",
            "demo", "mobile", "m", "app", "store", "portal"
        ]
    },
    "ports": {
        "common": [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 8080, 8443],
        "extended": [1, 2, 3, ..., 1024]
    },
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 RISE/3.0"
}
```

### Customizing Configuration

You can modify the `rise_config.json` file to:

- Change output directory
- Adjust thread count for concurrency
- Modify timeout values
- Customize subdomain wordlists
- Add or modify port ranges
- Change the user agent string

## Reports

RISE generates comprehensive reports in multiple formats:

### Report Formats

1. **JSON**: Structured data suitable for processing by other tools
2. **TXT**: Human-readable text format with detailed findings
3. **HTML**: Modern, responsive web report with interactive elements

### Report Contents

Each report includes:

- Executive summary of findings
- Detailed results for each scanning module
- Timestamps and duration information
- Error messages (if any)
- Metadata about the scan

Reports are saved in the output directory (default: `./rise_results`) with filenames like:
- `rise_report_example_com_20230815_143022.json`
- `rise_report_example_com_20230815_143022.txt`
- `rise_report_example_com_20230815_143022.html`

## Examples

### Example 1: Full Reconnaissance

```bash
python rise.py example.com --module all --format all
```

This will:
1. Perform DNS enumeration
2. Discover subdomains
3. Scan common ports
4. Detect web technologies
5. Generate reports in all formats

### Example 2: Targeted Port Scanning

```bash
python rise.py example.com --module port --ports extended
```

This will:
1. Scan all ports from 1 to 1024
2. Generate reports in all formats

### Example 3: Interactive Session

```bash
python rise.py
```

```
Enter target domain (e.g., example.com): example.com
[+] Target set to: example.com

============================================================
MENU
============================================================
  [1] DNS Enumeration
  [2] Subdomain Discovery
  [3] Port Scanning
  [4] Web Technology Detection
  [5] Run Full Reconnaissance (All Modules)
------------------------------------------------------------
  [6] Generate Report
  [7] Show Results Summary
  [0] Exit
============================================================
Enter your choice: 5
Enter port range for full scan [common/extended] (common): common
```

## Logging

RISE creates detailed logs in the `rise_logs` directory. Log files are named with timestamps:
- `rise_20230815_143022.log`

Log levels can be configured in the configuration file (`log_level` setting).

## Disclaimer

This tool is intended for educational purposes and authorized security testing only. Users are responsible for obtaining proper authorization before scanning any systems. The authors are not responsible for any misuse or illegal use of this software.
