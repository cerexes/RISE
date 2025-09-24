import argparse
import concurrent.futures
import json
import logging
import os
import re
import socket
import sys
import threading
import time
from collections import deque
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import requests

try:
    import dns.resolver
except ImportError:
    print("Error: 'dnspython' is not installed. Please run: pip install dnspython")
    sys.exit(1)

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("Error: 'beautifulsoup4' is not installed. Please run: pip install beautifulsoup4")
    sys.exit(1)


# --- CMS Signatures Database ---
CMS_SIGNATURES = {
    "WordPress": {"meta_generator": "WordPress", "html_comments": "wp-content", "path_indicators": ["/wp-content/", "/wp-includes/", "/wp-json/"]},
    "Joomla": {"meta_generator": "Joomla", "html_comments": "Joomla!", "path_indicators": ["/components/", "/modules/", "/templates/", "/media/"]},
    "Drupal": {"meta_generator": "Drupal", "html_comments": "Drupal", "path_indicators": ["/sites/", "/core/", "/misc/", "/profiles/"]},
    "Magento": {"meta_generator": "Magento", "html_comments": "Mage", "path_indicators": ["/static/frontend/", "/media/catalog/"]},
    "Prestashop": {"meta_generator": "PrestaShop", "html_comments": "PrestaShop", "path_indicators": ["/themes/", "/modules/", "/img/", "/js/"]},
    "OpenCart": {"meta_generator": "OpenCart", "html_comments": "OpenCart", "path_indicators": ["/catalog/view/", "/admin/controller/", "/system/storage/"]},
    "Shopify": {"meta_generator": "Shopify", "html_comments": "Shopify", "path_indicators": ["/cdn.shopify.com", "/assets/"]},
    "TYPO3": {"meta_generator": "TYPO3", "html_comments": "TYPO3", "path_indicators": ["/typo3conf/", "/typo3_src/", "/typo3temp/"]},
    "Ghost": {"meta_generator": "Ghost", "html_comments": "Ghost", "path_indicators": ["/ghost/", "/content/"]},
    "ExpressionEngine": {"meta_generator": "ExpressionEngine", "html_comments": "ExpressionEngine", "path_indicators": ["/themes/ee/"]},
    "Wix": {"meta_generator": "Wix.com", "html_comments": "wix.com", "path_indicators": ["/wixpress/"]},
    "Weebly": {"meta_generator": "Weebly", "html_comments": "weebly", "path_indicators": ["/files/theme/"]},
    "Squarespace": {"meta_generator": "Squarespace", "html_comments": "squarespace", "path_indicators": ["/config.json", "/universal/"]},
    "Blogger": {"meta_generator": "blogger", "html_comments": "blogger", "path_indicators": ["/feeds/posts/"]},
    "Bitrix": {"meta_generator": "Bitrix", "html_comments": "bitrix", "path_indicators": ["/bitrix/"]},
    "Django CMS": {"meta_generator": "Django", "html_comments": "django", "path_indicators": ["/static/django/"]},
    "Craft CMS": {"meta_generator": "Craft CMS", "html_comments": "craftcms", "path_indicators": ["/craft/"]},
    "Umbraco": {"meta_generator": "Umbraco", "html_comments": "umbraco", "path_indicators": ["/umbraco/"]},
    "MODX": {"meta_generator": "MODX", "html_comments": "modx", "path_indicators": ["/manager/assets/"]},
    "Contao": {"meta_generator": "Contao", "html_comments": "contao", "path_indicators": ["/contao/"]}
}


# --- Configuration Management ---
class Config:
    """Manages tool configuration from a JSON file with sane defaults."""

    def __init__(self, config_path: Path = Path("rise_config.json")):
        self.config_file = config_path
        self.data: Dict[str, Any] = {}
        self.load_config()

    def load_config(self):
        """Loads configuration from file or creates a default one."""
        if self.config_file.exists():
            try:
                with self.config_file.open('r') as f:
                    self.data = json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                logging.warning(f"Failed to load config: {e}. Using defaults.")
                self.data = self._default_config()
        else:
            self.data = self._default_config()
            self.save_config()

    def _default_config(self) -> Dict[str, Any]:
        """Provides default configuration settings."""
        return {
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
                "extended": list(range(1, 1025))
            },
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 RISE/3.0"
        }

    def save_config(self):
        """Saves the current configuration to the file."""
        try:
            with self.config_file.open('w') as f:
                json.dump(self.data, f, indent=4)
            logging.info(f"Configuration saved to {self.config_file}")
        except IOError as e:
            logging.error(f"Failed to save config: {e}")

    def get(self, key: str, default: Any = None) -> Any:
        """Retrieves a configuration value, supporting nested keys."""
        keys = key.split('.')
        value = self.data
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        return value


# --- Data Structures & Result Management ---
@dataclass
class ScanResult:
    """A structured container for the results of a single scan module."""
    target: str
    module: str
    timestamp: str
    results: List[str]
    success: bool
    duration: float
    error_message: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class ResultManager:
    """Thread-safe manager for collecting, storing, and exporting scan results."""

    def __init__(self, output_dir: str):
        self.results: List[ScanResult] = []
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def add_result(self, result: ScanResult):
        """Adds a scan result in a thread-safe manner."""
        with self._lock:
            self.results.append(result)
        logging.info(f"Result added for {result.module} on {result.target}")

    def export_json(self, filename: str) -> str:
        """Exports all collected results to a JSON file."""
        filepath = self.output_dir / filename
        try:
            with filepath.open('w') as f:
                json.dump([asdict(r) for r in self.results], f, indent=4)
            logging.info(f"Results exported to {filepath}")
            return str(filepath)
        except IOError as e:
            logging.error(f"Failed to export JSON results: {e}")
            return ""

    def get_summary(self) -> Dict[str, Any]:
        """Generates a summary of all scan results."""
        with self._lock:
            total_scans = len(self.results)
            successful_scans = sum(1 for r in self.results if r.success)
            modules_run = sorted(list(set(r.module for r in self.results)))
            total_findings = sum(len(r.results) for r in self.results if r.success)

            unique_findings = set()
            for r in self.results:
                if r.success:
                    unique_findings.update(r.results)

            return {
                "total_scans": total_scans,
                "successful_scans": successful_scans,
                "failed_scans": total_scans - successful_scans,
                "modules_executed": modules_run,
                "total_findings": total_findings,
                "unique_findings": len(unique_findings),
            }


# --- Utilities ---
def setup_logging(log_level: str = "INFO", log_dir: str = "logs"):
    """Configures structured logging to both file and console."""
    log_path = Path(log_dir)
    log_path.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = log_path / f"rise_{timestamp}.log"

    logging.basicConfig(
        level=getattr(logging, log_level.upper(), logging.INFO),
        format='%(asctime)s - %(levelname)-8s - %(threadName)s - %(message)s',
        handlers=[
            logging.FileHandler(log_filename),
            logging.StreamHandler(sys.stdout)
        ]
    )
    logging.info(f"RISE logging initialized. Log file: {log_filename}")


def validate_domain(domain: str) -> bool:
    """
    Validates a domain name against common standards and security checks.
    Removes protocol and trailing slashes.
    """
    if not domain:
        return False

    # Sanitize input
    if "://" in domain:
        domain = urlparse(domain).netloc
    domain = domain.strip('/').lower()

    if len(domain) > 253:
        return False

    # Regex for valid domain characters and structure
    pattern = re.compile(
        r'^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*'
        r'([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$'
    )
    if not re.match(pattern, domain):
        return False

    # Prevent path traversal and other injection attempts
    if ".." in domain or "/" in domain or "\\" in domain:
        return False

    return True


# --- Network Utilities ---
class NetworkUtils:
    """A collection of static methods for common network operations."""

    @staticmethod
    def resolve_domain(domain: str) -> Optional[str]:
        """Resolves a domain to its primary IPv4 address."""
        try:
            return socket.gethostbyname(domain)
        except socket.gaierror:
            logging.warning(f"Could not resolve domain: {domain}")
            return None

    @staticmethod
    def check_port(host: str, port: int, timeout: int = 3) -> bool:
        """Checks if a TCP port is open on a given host."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                return sock.connect_ex((host, port)) == 0
        except (socket.gaierror, socket.timeout, OSError):
            return False

# --- Helper Class for Email Harvesting ---
class EmailHarvester:
    """A multi-threaded web crawler to find email addresses."""
    def __init__(self, base_url: str, session: requests.Session, max_pages: int = 50, num_threads: int = 10):
        self.base_url = base_url
        self.session = session
        self.visited_urls = set()
        self.emails_found = set()
        self.urls_queue = deque()
        self.max_pages = max_pages
        self.num_threads = num_threads
        self.page_count = 0
        self._lock = threading.Lock()

    def crawl(self):
        """Starts the crawling process with multiple threads."""
        self.urls_queue.append(self.base_url)
        threads = [threading.Thread(target=self.worker) for _ in range(self.num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()  # Wait for all threads to complete their work

    def worker(self):
        """The target function for each crawling thread."""
        while True:
            try:
                with self._lock:
                    if not self.urls_queue or self.page_count >= self.max_pages:
                        break  # Stop condition for the thread
                    url = self.urls_queue.popleft()
                    if url in self.visited_urls:
                        continue
                    self.visited_urls.add(url)
                    self.page_count += 1
                
                response = self.session.get(url, timeout=10)
                if response.status_code == 200 and 'text/html' in response.headers.get('Content-Type', ''):
                    html_content = response.text
                    self.extract_emails(html_content)
                    self.extract_links(html_content, url)
            except IndexError:
                break  # Queue is empty, thread can finish
            except requests.RequestException as e:
                logging.warning(f"EmailHarvester error crawling {url}: {e}")

    def extract_emails(self, html_content: str):
        """Finds all emails in the given HTML content using regex."""
        emails = set(re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', html_content))
        with self._lock:
            new_emails = emails - self.emails_found
            self.emails_found.update(new_emails)

    def extract_links(self, html_content: str, current_url: str):
        """Parses HTML for new links to add to the crawl queue."""
        soup = BeautifulSoup(html_content, 'html.parser')
        new_urls_to_add = []
        for link_tag in soup.find_all('a', href=True):
            href = link_tag['href']
            full_url = urljoin(current_url, href)
            if self.is_valid_url(full_url):
                 with self._lock:
                    if full_url not in self.visited_urls and full_url not in self.urls_queue:
                        new_urls_to_add.append(full_url)
        if new_urls_to_add:
            with self._lock:
                self.urls_queue.extend(new_urls_to_add)

    def is_valid_url(self, url: str) -> bool:
        """Checks if a URL is on the same domain and uses a valid scheme."""
        parsed_base = urlparse(self.base_url)
        parsed_url = urlparse(url)
        return (parsed_url.scheme in ('http', 'https') and
                parsed_url.netloc == parsed_base.netloc)

# --- Core Scanning Modules ---
class ScannerModules:
    """
    Contains all scanning logic, with each major function representing a module.
    Designed for concurrency and robust error handling.
    """

    def __init__(self, config: Config, result_manager: ResultManager):
        self.config = config
        self.result_manager = result_manager
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': config.get('user_agent')})

    def _run_module(self, func, target, *args, **kwargs):
        """Wrapper to standardize module execution, timing, and result handling."""
        module_name = func.__name__
        logging.info(f"Starting module '{module_name}' for target '{target}'")
        start_time = time.time()
        results: List[str] = []
        error_message: Optional[str] = None
        metadata: Optional[Dict[str, Any]] = {}
        success = False

        try:
            results, metadata = func(target, *args, **kwargs)
            success = True
        except Exception as e:
            error_message = f"An unexpected error occurred in {module_name}: {e}"
            logging.error(error_message)

        duration = time.time() - start_time
        scan_result = ScanResult(
            target=target,
            module=module_name,
            timestamp=datetime.now().isoformat(),
            results=sorted(list(set(results))),
            success=success,
            duration=duration,
            error_message=error_message,
            metadata=metadata
        )
        self.result_manager.add_result(scan_result)
        logging.info(f"Finished module '{module_name}' in {duration:.2f}s. Success: {success}")

        print_scan_result(scan_result)

        return success

    def dns_enumeration(self, target: str) -> Tuple[List[str], Dict]:
        """Performs comprehensive DNS record enumeration."""
        results: List[str] = []
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.config.get('timeout', 10)

        for r_type in record_types:
            try:
                answers = resolver.resolve(target, r_type)
                for rdata in answers:
                    results.append(f"{r_type:<5} -> {str(rdata)}")
            except dns.resolver.NoAnswer:
                logging.debug(f"No {r_type} records found for {target}")
            except dns.resolver.NXDOMAIN:
                raise dns.resolver.NXDOMAIN(f"Domain '{target}' does not exist.")
            except dns.exception.DNSException as e:
                logging.warning(f"Error retrieving {r_type} records for {target}: {e}")

        return results, {"record_types_queried": record_types}

    def subdomain_enumeration(self, target: str) -> Tuple[List[str], Dict]:
        """Discovers subdomains using a concurrent wordlist brute-force approach."""
        found_subdomains: Set[str] = set()
        wordlist = self.config.get('wordlists.subdomains', [])
        max_threads = self.config.get('max_threads', 50)

        def check_subdomain(sub: str):
            domain_to_check = f"{sub}.{target}"
            ip = NetworkUtils.resolve_domain(domain_to_check)
            if ip:
                found_subdomains.add(f"{domain_to_check} -> {ip}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads, thread_name_prefix="Subdomain") as executor:
            list(executor.map(check_subdomain, wordlist))

        return list(found_subdomains), {"wordlist_size": len(wordlist)}

    def port_scanning(self, target: str, port_range: str) -> Tuple[List[str], Dict]:
        """Scans for open TCP ports concurrently."""
        open_ports: List[str] = []
        target_ip = NetworkUtils.resolve_domain(target)
        if not target_ip:
            raise ConnectionError(f"Could not resolve '{target}' to an IP address.")

        ports_to_scan = self.config.get(f'ports.{port_range}', [])
        if not ports_to_scan:
            raise ValueError(f"Port range '{port_range}' is not defined in config.")

        max_threads = self.config.get('max_threads', 50)
        timeout = self.config.get('timeout', 3)

        def scan_port(port: int):
            if NetworkUtils.check_port(target_ip, port, timeout):
                try:
                    service = socket.getservbyport(port, 'tcp')
                except OSError:
                    service = "unknown"
                open_ports.append(f"{port:<5}/tcp -> {service}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads, thread_name_prefix="PortScan") as executor:
            list(executor.map(scan_port, ports_to_scan))

        metadata = {
            "target_ip": target_ip,
            "port_range": port_range,
            "ports_scanned": len(ports_to_scan)
        }
        return open_ports, metadata

    def web_technology_detection(self, target: str) -> Tuple[List[str], Dict]:
        """Analyzes a web server to detect technologies, headers, and common files."""
        results: List[str] = []
        urls_to_check = [f"https://{target}", f"http://{target}"]
        final_url = ""

        for url in urls_to_check:
            try:
                response = self.session.get(url, timeout=self.config.get('timeout', 10), allow_redirects=True)
                final_url = response.url
                results.append(f"URL Tested: {url} -> Status: {response.status_code} (Final: {final_url})")

                server = response.headers.get('Server', 'N/A')
                powered_by = response.headers.get('X-Powered-By', 'N/A')
                results.append(f"Server Header: {server}")
                results.append(f"X-Powered-By: {powered_by}")

                sec_headers = {
                    'Strict-Transport-Security': 'Missing', 'Content-Security-Policy': 'Missing',
                    'X-Frame-Options': 'Missing', 'X-Content-Type-Options': 'Missing',
                }
                for header in sec_headers:
                    if header in response.headers:
                        sec_headers[header] = 'Present'
                for h, status in sec_headers.items():
                    results.append(f"Security Header '{h}': {status}")

                for path in ['/robots.txt', '/sitemap.xml', '/security.txt']:
                    try:
                        path_res = self.session.get(f"{url.rstrip('/')}{path}", timeout=5)
                        if path_res.status_code == 200:
                            results.append(f"Found accessible file: {path_res.url}")
                    except requests.RequestException:
                        pass
                break
            except requests.RequestException as e:
                logging.warning(f"Could not connect to {url}: {e}")

        if not final_url:
            raise ConnectionError("Could not connect to the target via HTTP or HTTPS.")

        return results, {"final_url": final_url}

    def cms_detection(self, target: str) -> Tuple[List[str], Dict]:
        """Identifies the Content Management System (CMS) used by the target website."""
        results: List[str] = []
        response = None
        final_url = ""

        for scheme in ["https", "http"]:
            url = f"{scheme}://{target}"
            try:
                res = self.session.get(url, timeout=self.config.get('timeout', 10), allow_redirects=True)
                if res.status_code < 400:
                    final_url = res.url
                    response = res
                    break
            except requests.RequestException:
                continue

        if not final_url or not response:
            raise ConnectionError("Could not connect to the target via HTTP or HTTPS to perform CMS detection.")

        soup = BeautifulSoup(response.content, 'html.parser')
        html_content = response.text

        # Check meta generator tag
        meta_tag = soup.find("meta", {"name": "generator"})
        if meta_tag and meta_tag.get("content"):
            meta_content = meta_tag.get("content", "")
            for cms, details in CMS_SIGNATURES.items():
                if details["meta_generator"].lower() in meta_content.lower():
                    results.append(f"Detected via meta tag: {cms}")
                    return results, {"method": "meta_generator", "url_checked": final_url}

        # Check HTML comments and page source
        for cms, details in CMS_SIGNATURES.items():
            if details["html_comments"].lower() in html_content.lower():
                results.append(f"Detected via page source: {cms}")
                return results, {"method": "html_source", "url_checked": final_url}

        # Check common paths
        base_url = f"{urlparse(final_url).scheme}://{urlparse(final_url).netloc}"
        for cms, details in CMS_SIGNATURES.items():
            for path in details["path_indicators"]:
                test_url = f"{base_url.rstrip('/')}{path}"
                try:
                    path_response = self.session.get(test_url, timeout=5, allow_redirects=True)
                    if path_response.status_code == 200:
                        results.append(f"Detected via path: {cms} (found {test_url})")
                        return results, {"method": "path_indicator", "url_checked": test_url}
                except requests.RequestException:
                    continue

        return results, {"method": "all", "url_checked": final_url}

    def email_harvesting(self, target: str) -> Tuple[List[str], Dict]:
        """Crawls a website to find and collect email addresses."""
        base_url = f"https://{target}"
        try:
            self.session.head(base_url, timeout=5)
        except requests.RequestException:
            base_url = f"http://{target}"  # Fallback to http

        max_pages = self.config.get("max_crawl_pages", 50)
        num_threads = self.config.get("max_threads", 10)
        
        harvester = EmailHarvester(
            base_url=base_url,
            session=self.session,
            max_pages=max_pages,
            num_threads=num_threads
        )
        
        logging.info(f"Starting email harvester crawl on {base_url} (max {max_pages} pages)")
        harvester.crawl()
        
        found_emails = list(harvester.emails_found)
        metadata = {
            "base_url_crawled": base_url,
            "pages_crawled": harvester.page_count,
            "emails_found_count": len(found_emails)
        }
        return found_emails, metadata

    def ip_geolocation(self, target: str) -> Tuple[List[str], Dict]:
        """Retrieves geolocation and network information for the target's IP."""
        results: List[str] = []
        target_ip = NetworkUtils.resolve_domain(target)
        if not target_ip:
            raise ConnectionError(f"Could not resolve '{target}' to an IP address.")

        api_url = f"http://ip-api.com/json/{target_ip}"
        try:
            response = self.session.get(api_url, timeout=self.config.get('timeout', 10))
            response.raise_for_status()
            data = response.json()

            if data.get('status') == 'success':
                keys_to_display = [
                    'query', 'country', 'city', 'regionName', 'zip', 'lat', 'lon',
                    'timezone', 'isp', 'org', 'as'
                ]
                for key in keys_to_display:
                    if key in data and data[key]:
                        results.append(f"{key.replace('_', ' ').title():<15} -> {data[key]}")
                if 'lat' in data and 'lon' in data:
                    map_link = f"https://www.google.com/maps?q={data['lat']},{data['lon']}"
                    results.append(f"{'Map Link':<15} -> {map_link}")
            else:
                raise ValueError(f"IP API returned an error: {data.get('message', 'Unknown error')}")

        except requests.RequestException as e:
            raise ConnectionError(f"Failed to retrieve IP information: {e}") from e

        return results, {"target_ip": target_ip}

    def run_all_modules(self, target: str, port_range: str) -> bool:
        """Executes all available scanning modules sequentially."""
        logging.info(f"Running all modules for target: {target}")
        all_success = True
        all_success &= self._run_module(self.dns_enumeration, target)
        all_success &= self._run_module(self.subdomain_enumeration, target)
        all_success &= self._run_module(self.port_scanning, target, port_range)
        all_success &= self._run_module(self.web_technology_detection, target)
        all_success &= self._run_module(self.cms_detection, target)
        all_success &= self._run_module(self.email_harvesting, target)
        all_success &= self._run_module(self.ip_geolocation, target)
        return all_success


# --- Reporting ---
def generate_report(result_manager: ResultManager, target: str, report_format: str):
    """Generates and saves reports in the specified formats."""
    logging.info(f"Generating '{report_format}' report for {target}")
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    base_filename = f"rise_report_{target.replace('.', '_')}_{timestamp}"

    if report_format in ["json", "all"]:
        result_manager.export_json(f"{base_filename}.json")
    if report_format in ["txt", "all"]:
        _generate_text_report(result_manager, target, f"{base_filename}.txt")
    if report_format in ["html", "all"]:
        _generate_html_report(result_manager, target, f"{base_filename}.html")
    print(f"\n[+] Reports generated in: {result_manager.output_dir.resolve()}")


def _generate_text_report(result_manager: ResultManager, target: str, filename: str):
    """Generates a detailed plain-text report."""
    filepath = result_manager.output_dir / filename
    summary = result_manager.get_summary()
    with filepath.open('w') as f:
        f.write("=" * 80 + "\n")
        f.write("RISE: Reconnaissance Intelligence & Synthesis Engine - Report\n")
        f.write("=" * 80 + "\n")
        f.write(f"Target: {target}\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write("--- Executive Summary ---\n")
        for key, value in summary.items():
            f.write(f"{key.replace('_', ' ').title():<20}: {value}\n")
        f.write("\n")
        for result in result_manager.results:
            f.write("-" * 80 + "\n")
            f.write(f"Module: {result.module.upper()}\n")
            f.write(f"Status: {'SUCCESS' if result.success else 'FAILED'}\n")
            f.write(f"Duration: {result.duration:.2f}s\n")
            if result.error_message:
                f.write(f"Error: {result.error_message}\n")
            if result.results:
                f.write(f"Findings ({len(result.results)}):\n")
                for item in result.results:
                    f.write(f"  - {item}\n")
            f.write("\n")


def _generate_html_report(result_manager: ResultManager, target: str, filename: str):
    """Generates a modern, responsive HTML report."""
    filepath = result_manager.output_dir / filename
    summary = result_manager.get_summary()
    html_template = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>RISE Report: {target}</title>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; margin: 0; background-color: #f8f9fa; color: #212529; }}
            .container {{ max-width: 1200px; margin: 2rem auto; padding: 2rem; background: #fff; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
            .header {{ text-align: center; border-bottom: 1px solid #dee2e6; padding-bottom: 1.5rem; margin-bottom: 2rem; }}
            .header h1 {{ margin: 0; font-size: 2.5rem; }}
            .summary {{ background-color: #e9ecef; padding: 1.5rem; border-radius: 8px; margin-bottom: 2rem; display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; }}
            .summary-item {{ background: #fff; padding: 1rem; border-radius: 6px; text-align: center; }}
            .summary-item strong {{ display: block; font-size: 1.5rem; }}
            .module {{ margin-bottom: 1.5rem; border: 1px solid #dee2e6; border-radius: 8px; overflow: hidden; }}
            .module-header {{ padding: 1rem 1.5rem; font-weight: bold; font-size: 1.2rem; display: flex; justify-content: space-between; align-items: center; }}
            .module-header.success {{ background-color: #d4edda; color: #155724; }}
            .module-header.failed {{ background-color: #f8d7da; color: #721c24; }}
            .module-content {{ padding: 1.5rem; }}
            .findings-list {{ list-style-type: none; padding: 0; }}
            .findings-list li {{ background-color: #f8f9fa; padding: 0.75rem; border-radius: 4px; margin-bottom: 0.5rem; font-family: "SF Mono", "Fira Code", "Consolas", monospace; }}
            .error-msg {{ color: #721c24; font-weight: bold; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>RISE Reconnaissance Report</h1>
                <p><strong>Target:</strong> {target}</p>
                <p><strong>Generated:</strong> {timestamp}</p>
            </div>
            <div class="summary">{summary_items}</div>
            {module_results}
        </div>
    </body>
    </html>"""
    summary_items_html = ""
    for key, value in summary.items():
        summary_items_html += f'<div class="summary-item"><span>{key.replace("_", " ").title()}</span><strong>{value}</strong></div>'
    module_results_html = ""
    for result in result_manager.results:
        status_class = "success" if result.success else "failed"
        findings_html = ""
        if result.results:
            findings_html = '<ul class="findings-list">'
            for item in result.results:
                findings_html += f'<li>{item}</li>'
            findings_html += '</ul>'
        elif result.error_message:
            findings_html = f'<p class="error-msg">Error: {result.error_message}</p>'
        else:
            findings_html = "<p>No findings.</p>"
        module_results_html += f"""
        <div class="module">
            <div class="module-header {status_class}">
                <span>{result.module.upper()}</span>
                <span>{result.duration:.2f}s</span>
            </div>
            <div class="module-content">{findings_html}</div>
        </div>"""
    report_content = html_template.format(
        target=target, timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        summary_items=summary_items_html, module_results=module_results_html
    )
    with filepath.open('w') as f:
        f.write(report_content)


# --- UI & Main Application Logic ---
def print_scan_result(result: ScanResult):
    """Formats and prints a single ScanResult to the console."""
    header = f" Results for {result.module.upper()} "
    print("\n\n" + f"{header:=^60}")
    if result.success:
        if result.results:
            print(f"Findings ({len(result.results)}):")
            for item in result.results:
                print(f"  [+] {item}")
        else:
            print("  [+] No findings for this module.")
    else:
        print(f"  [!] Module failed to run.")
        if result.error_message:
            print(f"  [!] Error: {result.error_message}")
    print(f"{'='*60}\n")


def display_banner():
    banner = """
██████╗ ██╗███████╗███████╗
██╔══██╗██║██╔════╝██╔════╝
██████╔╝██║███████╗█████╗
██╔══██╗██║╚════██║██╔══╝
██║  ██║██║███████║███████╗
╚═╝  ╚═╝╚═╝╚══════╝╚══════╝
Reconnaissance Intelligence & Synthesis Engine
    """
    print(banner)


def display_menu():
    """Displays the main menu for interactive mode."""
    print("\n" + "="*60)
    print("MENU")
    print("="*60)
    print("  [1] DNS Enumeration")
    print("  [2] Subdomain Discovery")
    print("  [3] Port Scanning")
    print("  [4] Web Technology Detection")
    print("  [5] CMS Detection")
    print("  [6] Email Harvesting")
    print("  [7] IP Geolocation")
    print("  [8] Run Full Reconnaissance (All Modules)")
    print("-" * 60)
    print("  [9] Generate Report")
    print("  [10] Show Results Summary")
    print("  [0] Exit")
    print("="*60)


def parse_arguments():
    """Parses command-line arguments for non-interactive use."""
    parser = argparse.ArgumentParser(
        description="RISE: A modular and concurrent reconnaissance tool.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('target', nargs='?', help='The target domain to scan (e.g., example.com).')
    parser.add_argument(
        '-m', '--module',
        choices=['dns', 'subdomain', 'port', 'web', 'cms', 'email', 'ip_geo', 'all'],
        help='Run a specific module or all modules.'
    )
    parser.add_argument(
        '--ports', choices=['common', 'extended'], default='common',
        help="Port range for port scanning (default: common)."
    )
    parser.add_argument(
        '--format', choices=['txt', 'json', 'html', 'all'], default='all',
        help="Report output format (default: all)."
    )
    parser.add_argument(
        '--no-interactive', action='store_true',
        help='Run in non-interactive mode. Requires a target and module.'
    )
    return parser.parse_args()


def main():
    """Main entry point for the RISE application."""
    args = parse_arguments()
    config = Config()
    setup_logging(config.get("log_level", "INFO"), "rise_logs")
    result_manager = ResultManager(config.get("output_dir", "./rise_results"))
    scanner = ScannerModules(config, result_manager)

    if args.no_interactive:
        if not args.target or not args.module:
            print("Error: Non-interactive mode requires a target and a module (--module).")
            sys.exit(1)
        target = args.target
        if not validate_domain(target):
            print(f"Error: Invalid target domain '{target}'.")
            sys.exit(1)
        if args.module == 'dns':
            scanner._run_module(scanner.dns_enumeration, target)
        elif args.module == 'subdomain':
            scanner._run_module(scanner.subdomain_enumeration, target)
        elif args.module == 'port':
            scanner._run_module(scanner.port_scanning, target, args.ports)
        elif args.module == 'web':
            scanner._run_module(scanner.web_technology_detection, target)
        elif args.module == 'cms':
            scanner._run_module(scanner.cms_detection, target)
        elif args.module == 'email':
            scanner._run_module(scanner.email_harvesting, target)
        elif args.module == 'ip_geo':
            scanner._run_module(scanner.ip_geolocation, target)
        elif args.module == 'all':
            scanner.run_all_modules(target, args.ports)
        generate_report(result_manager, target, args.format)
        print("\n[+] Non-interactive scan complete.")
        sys.exit(0)

    display_banner()
    target = ""
    while not target:
        try:
            raw_target = input("Enter target domain (e.g., example.com): ").strip()
            if validate_domain(raw_target):
                target = urlparse(f"//{raw_target}").netloc
                print(f"[+] Target set to: {target}")
            else:
                print("Error: Invalid domain format. Please try again.")
        except KeyboardInterrupt:
            print("\n\n[+] Exiting RISE. Goodbye!")
            sys.exit(0)

    while True:
        display_menu()
        try:
            choice = input("Enter your choice: ").strip()
            if choice == '1':
                scanner._run_module(scanner.dns_enumeration, target)
            elif choice == '2':
                scanner._run_module(scanner.subdomain_enumeration, target)
            elif choice == '3':
                port_range = input("Enter port range [common/extended] (common): ").strip().lower() or "common"
                if port_range not in ['common', 'extended']:
                    port_range = 'common'
                scanner._run_module(scanner.port_scanning, target, port_range)
            elif choice == '4':
                scanner._run_module(scanner.web_technology_detection, target)
            elif choice == '5':
                scanner._run_module(scanner.cms_detection, target)
            elif choice == '6':
                scanner._run_module(scanner.email_harvesting, target)
            elif choice == '7':
                scanner._run_module(scanner.ip_geolocation, target)
            elif choice == '8':
                port_range = input("Enter port range for full scan [common/extended] (common): ").strip().lower() or "common"
                if port_range not in ['common', 'extended']:
                    port_range = 'common'
                scanner.run_all_modules(target, port_range)
            elif choice == '9':
                if not result_manager.results:
                    print("\n[!] No results to report. Please run a scan first.")
                    continue
                report_format = input("Enter report format [txt/json/html/all] (all): ").strip().lower() or "all"
                if report_format not in ['txt', 'json', 'html', 'all']:
                    report_format = 'all'
                generate_report(result_manager, target, report_format)
            elif choice == '10':
                if not result_manager.results:
                    print("\n[!] No results to display. Please run a scan first.")
                    continue
                summary = result_manager.get_summary()
                print("\n--- Results Summary ---")
                for key, value in summary.items():
                    print(f"{key.replace('_', ' ').title():<20}: {value}")
            elif choice == '0':
                print("\n[+] Exiting RISE. Goodbye!")
                break
            else:
                print("\n[!] Invalid choice. Please select a valid option.")
        except KeyboardInterrupt:
            print("\n\n[+] Exiting RISE. Goodbye!")
            sys.exit(0)
        except Exception as e:
            logging.error(f"An error occurred in the main loop: {e}")
            print(f"\n[!] An unexpected error occurred: {e}")


if __name__ == "__main__":
    if not sys.version_info >= (3, 8):
        print("Error: RISE requires Python 3.8 or newer.")
        sys.exit(1)
    main()