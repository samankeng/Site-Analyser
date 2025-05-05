# backend/scanner/services/content_scanner.py

import requests
import logging
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)

class ContentScanner:
    """Scanner for website content analysis with detailed findings"""
    
    def __init__(self, url):
        self.url = url
        self.headers = {
            'User-Agent': 'Site-Analyser Security Scanner/1.0'
        }
    
    def scan(self):
        """Scan the target URL for content-related issues with detailed findings"""
        findings = []
        
        try:
            # Make request to target URL
            response = requests.get(self.url, headers=self.headers, timeout=10)
            
            # Check if content is accessible
            if response.status_code != 200:
                findings.append({
                    'name': 'Content Not Accessible',
                    'description': f'The website returned a non-200 status code: {response.status_code}',
                    'severity': 'medium',
                    'details': {
                        'status_code': response.status_code,
                        'response_text': response.text[:1000] if response.text else 'Empty response',
                        'page_url': self.url,
                        'impact': 'Content is not properly accessible, which may indicate server issues or deliberate access restrictions.',
                        'recommendation': 'Verify the URL is correct and the server is properly configured.'
                    }
                })
                return findings
            
            # Parse HTML
            content = response.text
            soup = BeautifulSoup(content, 'html.parser')
            
            # Check for SEO and content issues
            findings.extend(self._check_meta_tags(soup))
            findings.extend(self._check_broken_images(soup))
            findings.extend(self._check_content_quality(soup))
            findings.extend(self._check_accessibility(soup))
            findings.extend(self._check_javascript_use(soup))
            findings.extend(self._check_mobile_friendliness(soup))
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error scanning content for {self.url}: {str(e)}")
            findings.append({
                'name': 'Connection Error',
                'description': f'Failed to connect to {self.url}: {str(e)}',
                'severity': 'info',
                'details': {
                    'error': str(e),
                    'page_url': self.url
                }
            })
        
        return findings
    
    def _check_meta_tags(self, soup):
        findings = []
        
        # Check for essential meta tags with detailed information
        meta_tags = {
            'description': {
                'tag': soup.find('meta', attrs={'name': 'description'}),
                'importance': 'Essential for SEO - helps search engines understand page content',
                'recommendation': 'Add a meta description under 160 characters that summarizes the page content'
            },
            'viewport': {
                'tag': soup.find('meta', attrs={'name': 'viewport'}),
                'importance': 'Essential for mobile compatibility - controls how page displays on mobile devices',
                'recommendation': 'Add <meta name="viewport" content="width=device-width, initial-scale=1.0">'
            },
            'robots': {
                'tag': soup.find('meta', attrs={'name': 'robots'}),
                'importance': 'Controls search engine behavior - tells crawlers how to index your site',
                'recommendation': 'Add <meta name="robots" content="index, follow"> for normal indexing'
            },
            'charset': {
                'tag': soup.find('meta', attrs={'charset': True}) or soup.find('meta', attrs={'http-equiv': 'Content-Type'}),
                'importance': 'Defines character encoding - prevents character display issues',
                'recommendation': 'Add <meta charset="UTF-8"> at the beginning of the head section'
            }
        }
        
        for tag_name, tag_info in meta_tags.items():
            if not tag_info['tag']:
                findings.append({
                    'name': f'Missing {tag_name.capitalize()} Meta Tag',
                    'description': f'The website is missing the {tag_name} meta tag, which is important for SEO and proper display.',
                    'severity': 'low',
                    'details': {
                        'missing_tag': tag_name,
                        'importance': tag_info['importance'],
                        'page_url': self.url,
                        'impact': f'Missing {tag_name} meta tag can affect search engine visibility and user experience.',
                        'recommendation': tag_info['recommendation']
                    }
                })
            else:
                # For tags that exist, check if they're empty or too short
                content = tag_info['tag'].get('content', '')
                if tag_name == 'description' and (not content or len(content) < 50):
                    findings.append({
                        'name': 'Short or Empty Meta Description',
                        'description': f'The meta description is {"empty" if not content else "too short"} ({len(content)} characters).',
                        'severity': 'low',
                        'details': {
                            'current_content': content,
                            'current_length': len(content),
                            'page_url': self.url,
                            'impact': 'Short meta descriptions may not provide enough context for search engines or users.',
                            'recommendation': 'Provide a descriptive meta description between 50-160 characters.'
                        }
                    })
        
        return findings
    
    def _check_broken_images(self, soup):
        findings = []
        
        # Check for images without alt text with detailed information
        images = soup.find_all('img')
        missing_alt = []
        empty_alt = []
        missing_src = []
        
        for img in images:
            src = img.get('src', '')
            alt = img.get('alt')
            
            if not src:
                missing_src.append(img)
            elif not alt:
                missing_alt.append(img)
            elif alt.strip() == '':
                empty_alt.append(img)
        
        # Report images without alt text
        if missing_alt or empty_alt:
            total_missing = len(missing_alt) + len(empty_alt)
            examples = []
            
            # Prepare examples of images with issues
            for img in (missing_alt + empty_alt)[:5]:  # Limit to 5 examples
                src = img.get('src', '')
                if src:
                    # Convert relative URLs to absolute
                    if not (src.startswith('http://') or src.startswith('https://')):
                        src = urljoin(self.url, src)
                    examples.append(src)
            
            findings.append({
                'name': 'Images Missing Alt Text',
                'description': f'Found {total_missing} images without proper alt text, which is bad for accessibility and SEO.',
                'severity': 'low',
                'details': {
                    'missing_alt_count': len(missing_alt),
                    'empty_alt_count': len(empty_alt),
                    'total_count': total_missing,
                    'total_images': len(images),
                    'examples': examples,
                    'page_url': self.url,
                    'impact': 'Missing alt text makes images inaccessible to screen readers and impacts SEO.',
                    'recommendation': 'Add descriptive alt text to all images for better accessibility and SEO.'
                }
            })
        
        # Report images with missing src
        if missing_src:
            findings.append({
                'name': 'Images Missing Source',
                'description': f'Found {len(missing_src)} img tags without src attribute.',
                'severity': 'low',
                'details': {
                    'count': len(missing_src),
                    'page_url': self.url,
                    'impact': 'Images without source attributes will not load and may cause layout issues.',
                    'recommendation': 'Ensure all img tags have valid src attributes.'
                }
            })
        
        return findings
    
    def _check_content_quality(self, soup):
        findings = []
        
        # Extract text content
        text_elements = soup.find_all(['p', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'li'])
        text_content = ' '.join([elem.get_text() for elem in text_elements])
        
        # Check content length
        word_count = len(re.findall(r'\b\w+\b', text_content))
        if word_count < 300:
            findings.append({
                'name': 'Thin Content',
                'description': f'The page has only {word_count} words of text content, which may be considered thin content by search engines.',
                'severity': 'low',
                'details': {
                    'word_count': word_count,
                    'recommended_minimum': 300,
                    'page_url': self.url,
                    'impact': 'Pages with thin content may rank poorly in search results and provide limited value to users.',
                    'recommendation': 'Add more substantial, high-quality content to improve SEO and user experience.'
                }
            })
        
        # Check for keyword stuffing (high keyword density)
        if word_count > 0:
            words = re.findall(r'\b\w+\b', text_content.lower())
            word_freq = {}
            for word in words:
                if len(word) > 3:  # Ignore short words
                    word_freq[word] = word_freq.get(word, 0) + 1
            
            # Get top 5 most frequent words
            top_words = sorted(word_freq.items(), key=lambda x: x[1], reverse=True)[:5]
            high_density_words = []
            
            for word, count in top_words:
                density = (count / word_count) * 100
                if density > 5:  # If a word appears in more than 5% of all words
                    high_density_words.append({
                        'word': word,
                        'count': count,
                        'density': f"{density:.1f}%"
                    })
            
            if high_density_words:
                findings.append({
                    'name': 'Possible Keyword Stuffing',
                    'description': f'Found {len(high_density_words)} words with unusually high density, which may be considered keyword stuffing.',
                    'severity': 'low',
                    'details': {
                        'high_density_words': high_density_words,
                        'total_words': word_count,
                        'page_url': self.url,
                        'impact': 'Keyword stuffing may trigger search engine penalties and create a poor user experience.',
                        'recommendation': 'Use keywords naturally in your content and maintain a balanced word frequency.'
                    }
                })
        
        # Check for duplicate content paragraphs
        paragraphs = soup.find_all('p')
        if len(paragraphs) > 3:  # Only check if there are enough paragraphs
            paragraph_texts = [p.get_text().strip() for p in paragraphs if len(p.get_text().strip()) > 20]
            duplicate_count = len(paragraph_texts) - len(set(paragraph_texts))
            
            if duplicate_count > 0:
                findings.append({
                    'name': 'Duplicate Paragraphs',
                    'description': f'Found {duplicate_count} duplicate paragraphs on the page.',
                    'severity': 'low',
                    'details': {
                        'duplicate_count': duplicate_count,
                        'total_paragraphs': len(paragraphs),
                        'page_url': self.url,
                        'impact': 'Duplicate content can negatively impact SEO and provides a poor user experience.',
                        'recommendation': 'Remove or revise duplicate paragraphs to create unique content.'
                    }
                })
        
        return findings
    
          

    def _check_accessibility(self, soup):
        findings = []
        
        # Check for heading structure with detailed information
        headings = soup.find_all(['h1', 'h2', 'h3', 'h4', 'h5', 'h6'])
        heading_levels = [int(h.name[1]) for h in headings]
        
        if headings:
            # Check if H1 exists
            if 1 not in heading_levels:
                findings.append({
                    'name': 'Missing H1 Heading',
                    'description': 'The page is missing an H1 heading, which is important for SEO and document structure.',
                    'severity': 'low',
                    'details': {
                        'heading_structure': [f"H{level}" for level in sorted(set(heading_levels))],
                        'page_url': self.url,
                        'impact': 'Missing H1 heading can negatively impact SEO and accessibility.',
                        'recommendation': 'Add a single H1 heading that describes the main topic of the page.'
                    }
                })
            
            # Check for multiple H1 headings
            h1_count = heading_levels.count(1)
            if h1_count > 1:
                h1_texts = [h.get_text() for h in soup.find_all('h1')]
                findings.append({
                    'name': 'Multiple H1 Headings',
                    'description': f'The page has {h1_count} H1 headings, but should ideally have only one.',
                    'severity': 'low',
                    'details': {
                        'h1_count': h1_count,
                        'h1_headings': h1_texts[:5],  # Include the first 5 H1 headings
                        'page_url': self.url,
                        'impact': 'Multiple H1 headings can confuse search engines about the main topic of the page.',
                        'recommendation': 'Use only one H1 heading per page, and use H2-H6 for subsections.'
                    }
                })
        else:
            findings.append({
                'name': 'No Headings Found',
                'description': 'The page does not contain any heading elements (H1-H6).',
                'severity': 'medium',
                'details': {
                    'page_url': self.url,
                    'impact': 'Pages without headings are difficult to navigate and have poor accessibility and SEO.',
                    'recommendation': 'Add proper heading structure starting with an H1 for the main title and using H2-H6 for sections.'
                }
            })
        
        # Check for form labels with detailed information
        forms = soup.find_all('form')
        for i, form in enumerate(forms):
            inputs = form.find_all(['input', 'textarea', 'select'])
            unlabeled_inputs = []
            
            for input_field in inputs:
                if input_field.get('type') not in ['hidden', 'submit', 'button', 'image', 'file']:
                    input_id = input_field.get('id')
                    input_name = input_field.get('name', '(no name)')
                    input_type = input_field.get('type', input_field.name)
                    
                    # Check if input has an associated label
                    has_label = False
                    if input_id:
                        label = soup.find('label', attrs={'for': input_id})
                        if label:
                            has_label = True
                    
                    # Check for aria-label as an alternative
                    if not has_label and not input_field.get('aria-label') and not input_field.get('aria-labelledby'):
                        unlabeled_inputs.append({
                            'type': input_type,
                            'name': input_name,
                            'id': input_id or '(no id)',
                            'html': str(input_field)[:100]  # Truncate HTML if too long
                        })
            
            if unlabeled_inputs:
                findings.append({
                    'name': 'Form Fields Missing Labels',
                    'description': f'Found {len(unlabeled_inputs)} form fields without proper labels in form #{i+1}.',
                    'severity': 'low',
                    'details': {
                        'form_position': i+1,
                        'form_action': form.get('action', '(no action)'),
                        'unlabeled_fields': unlabeled_inputs,
                        'page_url': self.url,
                        'impact': 'Form fields without labels are inaccessible to screen readers and difficult for users to understand.',
                        'recommendation': 'Add labels with for attributes matching the input IDs, or use aria-label attributes.'
                    }
                })
        
        return findings
    
    def _check_javascript_use(self, soup):
        """Check for JavaScript-related issues"""
        findings = []
        
        # Check for inline JavaScript
        inline_scripts = soup.find_all('script', src=None)
        inline_js_count = len([s for s in inline_scripts if s.string and len(s.string.strip()) > 0])
        
        if inline_js_count > 0:
            findings.append({
                'name': 'Inline JavaScript Detected',
                'description': f'Found {inline_js_count} inline script tags on the page.',
                'severity': 'low',
                'details': {
                    'inline_script_count': inline_js_count,
                    'page_url': self.url,
                    'impact': 'Inline JavaScript can cause performance issues and makes Content Security Policy implementation harder.',
                    'recommendation': 'Move JavaScript to external files for better caching and maintenance.'
                }
            })
        
        # Check for JavaScript libraries loaded from external CDNs
        external_js = soup.find_all('script', src=True)
        external_js_srcs = [s.get('src', '') for s in external_js]
        cdn_js = [src for src in external_js_srcs if 'cdn' in src or '//' in src]
        
        if cdn_js:
            # Check for SRI (Subresource Integrity)
            no_integrity = [src for src in cdn_js if not soup.find('script', src=src).get('integrity')]
            
            if no_integrity:
                findings.append({
                    'name': 'CDN Resources Without Integrity Checks',
                    'description': f'Found {len(no_integrity)} external scripts without integrity attributes.',
                    'severity': 'low',
                    'details': {
                        'scripts_without_integrity': no_integrity[:5],  # List first 5
                        'page_url': self.url,
                        'impact': 'External scripts without integrity checks could be tampered with by attackers.',
                        'recommendation': 'Add integrity attributes to external script tags to prevent tampering.'
                    }
                })
        
        return findings
    
    def _check_mobile_friendliness(self, soup):
        """Check basic mobile-friendliness indicators"""
        findings = []
        
        # Check viewport meta tag
        viewport = soup.find('meta', attrs={'name': 'viewport'})
        if viewport:
            # Check for responsive viewport settings
            content = viewport.get('content', '')
            if 'width=device-width' not in content:
                findings.append({
                    'name': 'Non-Responsive Viewport Setting',
                    'description': 'The viewport meta tag lacks "width=device-width" setting for responsive design.',
                    'severity': 'low',
                    'details': {
                        'current_viewport': content,
                        'page_url': self.url,
                        'impact': 'Without proper viewport settings, the page may not display correctly on mobile devices.',
                        'recommendation': 'Set viewport to "width=device-width, initial-scale=1.0" for responsive design.'
                    }
                })
        
        # Check for fixed-width elements that could cause horizontal scrolling
        elements_with_width = soup.select('[style*="width"]')
        fixed_width_elements = []
        
        for element in elements_with_width:
            style = element.get('style', '')
            # Look for fixed width in pixels
            if re.search(r'width:\s*\d+px', style, re.IGNORECASE):
                fixed_width_elements.append({
                    'element': element.name,
                    'style': style
                })
        
        if fixed_width_elements:
            findings.append({
                'name': 'Fixed-Width Elements Detected',
                'description': f'Found {len(fixed_width_elements)} elements with fixed width that may cause horizontal scrolling on mobile.',
                'severity': 'low',
                'details': {
                    'fixed_width_elements': fixed_width_elements[:5],  # List first 5
                    'page_url': self.url,
                    'impact': 'Fixed-width elements can cause horizontal scrolling on mobile devices, degrading user experience.',
                    'recommendation': 'Use responsive width (%, em, rem) or max-width instead of fixed pixel widths.'
                }
            })
        
        return findings