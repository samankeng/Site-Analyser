
import requests
import logging
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

class HeaderScanner:
    def __init__(self, url, max_pages_to_scan=10):
        self.url = url
        self.max_pages_to_scan = max_pages_to_scan
        self.visited_urls = set()
        self.headers = {
            'User-Agent': 'Site-Analyser Header Scanner/1.0'
        }

    def scan(self):
        findings = []
        urls_to_scan = [self.url]

        while urls_to_scan and len(self.visited_urls) < self.max_pages_to_scan:
            page_url = urls_to_scan.pop(0)
            if page_url in self.visited_urls:
                continue

            try:
                response = requests.get(page_url, headers=self.headers, timeout=10)
                if response.status_code != 200:
                    continue

                self.visited_urls.add(page_url)
                findings.extend(self._check_security_headers(response.headers, page_url))

                soup = BeautifulSoup(response.text, 'html.parser')
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    if not href.startswith('#'):
                        full_url = urljoin(page_url, href)
                        if self._is_internal_url(full_url) and full_url not in self.visited_urls:
                            urls_to_scan.append(full_url)

            except requests.RequestException as e:
                logger.warning(f"Header scan request failed for {page_url}: {e}")
                findings.append({
                    'name': 'Header Scan Connection Error',
                    'description': str(e),
                    'severity': 'info',
                    'details': {
                        'error': str(e),
                        'page_url': page_url
                    }
                })

        return findings

    def _is_internal_url(self, url):
        return urlparse(url).netloc == urlparse(self.url).netloc

    def _check_security_headers(self, headers, page_url):
        findings = []
        required_headers = {
            'Strict-Transport-Security': 'Enforce secure connections (HSTS)',
            'Content-Security-Policy': 'Prevent XSS and content injection',
            'X-Content-Type-Options': 'Prevent MIME-type sniffing',
            'X-Frame-Options': 'Prevent clickjacking',
            'X-XSS-Protection': 'Enable XSS filtering'
        }

        for header, recommendation in required_headers.items():
            if header not in headers:
                findings.append({
                    'name': f'Missing Security Header: {header}',
                    'description': f'The {header} header is missing.',
                    'severity': 'medium',
                    'details': {
                        'recommendation': recommendation,
                        'page_url': page_url
                    }
                })
        return findings
