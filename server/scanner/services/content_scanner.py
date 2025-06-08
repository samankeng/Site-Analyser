import requests
import logging
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)

class ContentScanner:
    def __init__(self, url):
        self.url = url
        self.headers = {
            'User-Agent': 'Site-Analyser Security Scanner/1.0'
        }
        self.visited_urls = set()

    def scan(self):
        findings = []
        urls_to_scan = [self.url]

        while urls_to_scan:
            current_url = urls_to_scan.pop(0)
            if current_url in self.visited_urls:
                continue

            try:
                response = requests.get(current_url, headers=self.headers, timeout=10)
                final_url = response.url
                self.visited_urls.add(final_url)

                if response.status_code != 200:
                    findings.append({
                        'name': 'Content Not Accessible',
                        'description': f'The website returned a non-200 status code: {response.status_code}',
                        'severity': 'medium',
                        'details': {
                            'status_code': response.status_code,
                            'response_text': response.text[:1000] if response.text else 'Empty response',
                            'page_url': final_url,
                            'impact': 'Content is not properly accessible.',
                            'recommendation': 'Verify the URL is correct.'
                        }
                    })
                    continue

                soup = BeautifulSoup(response.text, 'html.parser')

                findings.extend(self._check_meta_tags(soup, final_url))
                findings.extend(self._check_broken_images(soup, final_url))
                findings.extend(self._check_content_quality(soup, final_url))
                findings.extend(self._check_accessibility(soup, final_url))
                findings.extend(self._check_javascript_use(soup, final_url))
                findings.extend(self._check_mobile_friendliness(soup, final_url))

                for link in soup.find_all('a', href=True):
                    href = link['href']
                    if not href.startswith('#'):
                        next_url = urljoin(final_url, href)
                        if self._is_internal_url(next_url) and next_url not in self.visited_urls:
                            urls_to_scan.append(next_url)

            except requests.exceptions.RequestException as e:
                logger.error(f"Error scanning {current_url}: {str(e)}")
                findings.append({
                    'name': 'Connection Error',
                    'description': f'Failed to connect to {current_url}: {str(e)}',
                    'severity': 'info',
                    'details': {
                        'error': str(e),
                        'page_url': current_url
                    }
                })

        return findings

    def _is_internal_url(self, url):
        return urlparse(url).netloc == urlparse(self.url).netloc

    def _check_meta_tags(self, soup, page_url):
        findings = []
        if not soup.find('meta', attrs={'name': 'description'}):
            findings.append({
                'name': 'Missing Description Meta Tag',
                'description': 'The website is missing the description meta tag.',
                'severity': 'low',
                'details': {
                    'page_url': page_url,
                    'impact': 'Affects SEO and display in search engines.',
                    'recommendation': 'Add a meta description under 160 characters.'
                }
            })
        if not soup.find('meta', attrs={'name': 'robots'}):
            findings.append({
                'name': 'Missing Robots Meta Tag',
                'description': 'The website is missing the robots meta tag.',
                'severity': 'low',
                'details': {
                    'page_url': page_url,
                    'impact': 'Affects how search engines index the page.',
                    'recommendation': 'Add <meta name="robots" content="index, follow">.'
                }
            })
        return findings

    def _check_broken_images(self, soup, page_url):
        findings = []
        images = soup.find_all('img')
        for img in images:
            if not img.get('alt'):
                findings.append({
                    'name': 'Missing Image Alt Text',
                    'description': 'An image is missing alt text.',
                    'severity': 'low',
                    'details': {
                        'page_url': urljoin(page_url, img.get('src', '')),
                        'impact': 'Reduces accessibility and SEO.',
                        'recommendation': 'Add descriptive alt text to all images.'
                    }
                })
        return findings

    def _check_content_quality(self, soup, page_url):
        findings = []
        text = soup.get_text(separator=' ', strip=True)
        word_count = len(text.split())
        if word_count < 50:
            findings.append({
                'name': 'Thin Content',
                'description': f'The page has only {word_count} words of text content.',
                'severity': 'low',
                'details': {
                    'page_url': page_url,
                    'impact': 'Thin content may rank poorly in search engines.',
                    'recommendation': 'Add more meaningful content to the page.'
                }
            })
        return findings

    def _check_accessibility(self, soup, page_url):
        findings = []
        headings = soup.find_all(['h1', 'h2', 'h3', 'h4', 'h5', 'h6'])
        heading_levels = [int(h.name[1]) for h in headings]
        if headings and 1 not in heading_levels:
            findings.append({
                'name': 'Missing H1 Heading',
                'description': 'The page is missing an H1 heading.',
                'severity': 'low',
                'details': {
                    'heading_structure': [f"H{level}" for level in sorted(set(heading_levels))],
                    'page_url': page_url,
                    'impact': 'Impacts SEO and document accessibility.',
                    'recommendation': 'Add a single H1 heading describing the page.'
                }
            })
        return findings

    def _check_javascript_use(self, soup, page_url):
        findings = []
        inline_scripts = soup.find_all('script', src=False)
        if inline_scripts:
            findings.append({
                'name': 'Inline JavaScript Detected',
                'description': f'Found {len(inline_scripts)} inline script tags.',
                'severity': 'low',
                'details': {
                    'page_url': page_url,
                    'impact': 'May reduce performance and complicate security policies.',
                    'recommendation': 'Move scripts to external files.'
                }
            })
        return findings

    def _check_mobile_friendliness(self, soup, page_url):
        findings = []
        viewport = soup.find('meta', attrs={'name': 'viewport'})
        if not viewport:
            findings.append({
                'name': 'Missing Viewport Meta Tag',
                'description': 'The page is missing a viewport meta tag.',
                'severity': 'low',
                'details': {
                    'page_url': page_url,
                    'impact': 'Affects mobile responsiveness.',
                    'recommendation': 'Add <meta name="viewport" content="width=device-width, initial-scale=1.0">'
                }
            })
        return findings
