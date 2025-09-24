# RISE
Reconnaissance Intelligence &amp; Synthesis Engine (under development)

A simple recon tool I'm making, the tool is in its beta phase, yet to add many features.

RISE is a comprehensive, modular reconnaissance tool designed for security professionals and penetration testers. It performs automated intelligence gathering on target domains through multiple concurrent scanning modules.

## Features

- **Modular Architecture**: Each reconnaissance task is implemented as a separate module
- **Concurrent Processing**: Utilizes multi-threading for efficient scanning
- **Multiple Scan Modules**:
  - DNS Enumeration
  - Subdomain Discovery
  - Port Scanning
  - Web Technology Detection
  - CMS Detection
  - Email Harvesting
  - IP Geolocation
- **Comprehensive Reporting**: Generate reports in JSON, TXT, and HTML formats
- **Interactive & Non-Interactive Modes**: Suitable for both manual testing and automation
- **Configurable**: Customizable through JSON configuration file

## Installation

### Prerequisites

- Python 3.8 or newer
- Required Python packages:
  - `dnspython`
  - `beautifulsoup4`
  - `requests`

### Setup

1. Clone or download the `rise.py` script
2. Install dependencies:
   ```bash
   pip install dnspython beautifulsoup4 requests
   ```
3. Make the script executable (optional):
   ```bash
   chmod +x rise.py
   ```

## Usage

### Interactive Mode

Run the script without arguments to enter interactive mode:

```bash
python rise.py
```

Follow the on-screen menu to select scanning modules and generate reports.

### Non-Interactive Mode

For automated scanning, use command-line arguments:

```bash
python rise.py <target> --module <module_name> [options]
```

#### Available Modules

- `dns`: DNS Enumeration
- `subdomain`: Subdomain Discovery
- `port`: Port Scanning
- `web`: Web Technology Detection
- `cms`: CMS Detection
- `email`: Email Harvesting
- `ip_geo`: IP Geolocation
- `all`: Run all modules

#### Examples

1. Run full reconnaissance on example.com:
   ```bash
   python rise.py example.com --module all
   ```

2. Perform only port scanning with extended ports:
   ```bash
   python rise.py example.com --module port --ports extended
   ```

3. Run CMS detection and generate HTML report:
   ```bash
   python rise.py example.com --module cms --format html
   ```

## Configuration

RISE uses a JSON configuration file (`rise_config.json`) for customization. On first run, it creates a default configuration file with these settings:

- `output_dir`: Directory for storing results (default: `./rise_results`)
- `max_threads`: Maximum number of threads for concurrent operations (default: 50)
- `timeout`: Request timeout in seconds (default: 10)
- `log_level`: Logging level (default: `INFO`)
- `wordlists`: Subdomain wordlist for enumeration
- `ports`: Port ranges for scanning (common and extended)
- `user_agent`: Custom user agent string

You can modify this file to customize RISE's behavior.

## Modules Description

### DNS Enumeration
Performs comprehensive DNS record enumeration (A, AAAA, MX, NS, TXT, CNAME, SOA).

### Subdomain Discovery
Discovers subdomains using a concurrent wordlist brute-force approach.

### Port Scanning
Scans for open TCP ports concurrently. Supports two port ranges:
- `common`: 21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 8080, 8443
- `extended`: All ports from 1 to 1024

### Web Technology Detection
Analyzes web servers to detect technologies, headers, and common files like robots.txt and sitemap.xml.

### CMS Detection
Identifies the Content Management System (CMS) used by the target website through:
- Meta generator tags
- HTML comments
- Common path indicators

### Email Harvesting
Crawls websites to find and collect email addresses using multi-threaded web crawling.

### IP Geolocation
Retrieves geolocation and network information for the target's IP address using external APIs.

## Reporting

RISE generates comprehensive reports in multiple formats:

- **JSON**: Machine-readable format with detailed results
- **TXT**: Human-readable text report with executive summary
- **HTML**: Modern, responsive HTML report with interactive elements

Reports are saved in the output directory (default: `./rise_results`) with timestamps.

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## Disclaimer

This tool is for educational and authorized security testing purposes only. Users are responsible for obtaining proper authorization before scanning any target systems. The developers are not responsible for any misuse or illegal use of this software.
