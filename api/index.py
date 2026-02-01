from flask import Flask, render_template_string, request, jsonify
import requests
import threading
import queue
import re
import json
import time
import random
import concurrent.futures
from bs4 import BeautifulSoup
from urllib.parse import quote_plus, urljoin, urlparse
import urllib3
from datetime import datetime
import socket
import ssl

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

PAYPAL_DORKS = [
    'inurl:"/donate" (intext:"PayPal Commerce" | intext:"paypal.com/donate")',
    'inurl:"/donate" intext:"donate.paypal.com" | "paypal.me/donate"',
    'inurl:"donate" (intext:"business=paypal" | intext:"hosted_button_id")',
    'inurl:"/donate" (intext:"paypal.com/cgi-bin/webscr" intext:"donation")',
    'inurl:"donate" (intext:"paypal buttons" | intext:"paypal donation")',
    'inurl:"/donate" intext:"src=\'https://www.paypal.com/donate"',
    'inurl:"donate" (intext:"paypal.com/donate/buttons" | intext:"paypal.com/donate/script")',
    'inurl:"/donation" intext:"paypal" (intext:"commerce" | intext:"checkout")',
    'inurl:"donate.php" (intext:"paypal" | intext:"pp-donate-button")',
    'inurl:"donate" filetype:html intext:"paypal.com/donate" intext:"button"'
]

BRAINTREE_DORKS = [
    'inurl:/donate intext:"braintree" intext:"payment"',
    'inurl:/donate (intext:"Powered by Braintree" | intext:"Braintree API")',
    'inurl:"donation" (filetype:php | filetype:html) intext:"braintree"',
    'inurl:/donate intext:"payment gateway" "braintree"',
    'intitle:"Donate" intext:"Braintree" -inurl:github',
    'inurl:"donate.php" intext:"Braintree_Configuration"',
    '"donate" "Braintree" "sandbox" "merchant"',
    'inurl:"/donate/" intext:"checkout.js" "braintree"',
    'inurl:"/donations" intext:"data-braintree" OR "data-paypal"',
    '"Make a Donation" (intext:"Braintree" | intext:"PayPal Commerce")'
]

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:123.0) Gecko/20100101 Firefox/123.0',
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 OPR/108.0.0.0'
]

GATEWAYS = [
    'Stripe', 'PayPal', 'Braintree', 'Razorpay', 'Authorize.Net',
    '2Checkout', 'Mollie', 'Google Pay', 'Checkout.com', 'BlueSnap',
    'Adyen', 'WooCommerce', 'Shopify', 'Square', 'Amazon Pay',
    'Skrill', 'WePay', 'PayU', 'Payoneer', 'TransferWise', 'SagePay',
    'WorldPay', 'Klarna', 'Afterpay', 'Affirm', 'iZettle', 'Paytm',
    'Alipay', 'WeChat Pay', 'Apple Pay', 'Samsung Pay', 'Visa Checkout',
    'Masterpass', 'Dwolla', 'PayTrace', 'Fortumo', 'Boleto', 'Pagar.me',
    'MercadoPago', 'WebMoney', 'Yandex.Money', 'Qiwi', 'GiroPay', 'Sofort',
    'Ideal', 'Bancontact', 'Multibanco', 'Przelewy24', 'Payeer', 'Perfect Money',
    'PaySafeCard', 'Epay', 'Neteller', 'Moneybookers', 'ClickandBuy', 'CashU'
]

EXTENDED_KEYWORDS = [
    'checkout', 'cart', 'payment', 'billing', 'shipping', 'order', 'purchase',
    'buy now', 'add to cart', 'secure checkout', 'pay with', 'credit card',
    'debit card', 'bank transfer', 'crypto payment', 'wallet', 'transaction',
    'invoice', 'receipt', 'subscription', 'membership', 'plan', 'pricing',
    'store', 'shop', 'ecommerce', 'marketplace', 'vendor', 'merchant',
    'gateway', 'processor', 'api key', 'secret key', 'public key', 'token',
    'auth', 'capture', 'refund', 'chargeback', 'dispute', 'fraud', 'risk',
    'compliance', 'pci dss', '3d secure', 'cvv', 'expiry', 'cardholder'
]

DONATE_KEYWORDS = [
    'donate', 'donation', 'contribute', 'support', 'funding', 'sponsor',
    'patron', 'charity', 'nonprofit', 'fundraiser', 'campaign'
]

class ProXyMaNaGeR:
    def __init__(self, proxy_file=None):
        self.proxies = []
        if proxy_file:
            try:
                with open(proxy_file, 'r') as f:
                    self.proxies = [l.strip() for l in f if l.strip()]
            except:
                pass
        self.current_index = 0
        self.lock = threading.Lock()

    def get_proxy(self):
        if not self.proxies:
            return None
        with self.lock:
            proxy = self.proxies[self.current_index]
            self.current_index = (self.current_index + 1) % len(self.proxies)
            return {"http": proxy, "https": proxy}

class PaYLoAdGeNeRaToR:
    @staticmethod
    def generate_dorks(base_keywords):
        formats = [
            'site:.com "{kw}"',
            'inurl:checkout "{kw}"',
            'intitle:"index of" "{kw}"',
            'intext:"powered by {kw}"',
            'filetype:php "{kw}"',
            '"{kw}" "add to cart"',
            '"{kw}" "stripe checkout"',
            '"{kw}" "paypal checkout"',
            '"{kw}" "credit card accepted"',
            '"{kw}" "secure payment"'
        ]
        generated = []
        for kw in base_keywords:
            for fmt in formats:
                generated.append(fmt.format(kw=kw))
        return generated

class AdVaNcEdVaLiDaToR:
    @staticmethod
    def check_ssl(hostname):
        try:
            context = ssl.create_default_context()
            with context.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                s.settimeout(5)
                s.connect((hostname, 443))
                cert = s.getpeercert()
                return cert
        except:
            return None

    @staticmethod
    def check_security_headers(headers):
        security_headers = [
            'Content-Security-Policy',
            'Strict-Transport-Security',
            'X-Content-Type-Options',
            'X-Frame-Options',
            'X-XSS-Protection'
        ]
        found = {}
        for h in security_headers:
            if h in headers:
                found[h] = headers[h]
        return found

class DaTaExPoRtEr:
    @staticmethod
    def to_csv(results):
        csv_data = "URL,Domain,Gateways,Score,Title,Timestamp\n"
        for res in results:
            gateways = ', '.join(res['gateways'])
            title = res['metadata'].get('title', '').replace(',', ';')
            csv_data += f"{res['url']},{res['domain']},{gateways},{res['score']},{title},{res['timestamp']}\n"
        return csv_data

class NeTwOrKuTiLs:
    @staticmethod
    def get_ip_info(ip):
        try:
            res = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5)
            return res.json()
        except:
            return {}

    @staticmethod
    def resolve_dns(domain):
        try:
            return socket.gethostbyname(domain)
        except:
            return None

class CoNtEnTaNaLyZeR:
    def __init__(self):
        self.patterns = {
            'api_keys': r'(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24}',
            'google_api': r'AIza[0-9A-Za-z-_]{35}',
            'mailchimp': r'[0-9a-f]{32}-us[0-9]{1,2}',
            'aws_key': r'AKIA[0-9A-Z]{16}'
        }

    def find_leaks(self, html):
        leaks = {}
        for name, pattern in self.patterns.items():
            found = re.findall(pattern, html)
            if found:
                leaks[name] = list(set(found))
        return leaks

class SyStEmMoNiToR:
    def __init__(self):
        self.start_time = time.time()
        self.last_check = time.time()
        self.processed_since_last = 0

    def get_speed(self, current_total):
        now = time.time()
        elapsed = now - self.last_check
        if elapsed < 1: return 0
        speed = (current_total - self.processed_since_last) / elapsed
        self.last_check = now
        self.processed_since_last = current_total
        return speed

class RaTeLiMiTeR:
    def __init__(self, calls_per_second):
        self.delay = 1.0 / calls_per_second
        self.last_call = 0
        self.lock = threading.Lock()

    def wait(self):
        with self.lock:
            elapsed = time.time() - self.last_call
            if elapsed < self.delay:
                time.sleep(self.delay - elapsed)
            self.last_call = time.time()

class CaChEMaNaGeR:
    def __init__(self, expiry=3600):
        self.cache = {}
        self.expiry = expiry

    def set(self, key, value):
        self.cache[key] = (value, time.time())

    def get(self, key):
        if key in self.cache:
            val, ts = self.cache[key]
            if time.time() - ts < self.expiry:
                return val
        return None

class ThReAdSaFeCoUnTeR:
    def __init__(self):
        self.value = 0
        self.lock = threading.Lock()

    def increment(self):
        with self.lock:
            self.value += 1
            return self.value

class VaLiDaTiOnLoGiC:
    @staticmethod
    def is_valid_url(url):
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False

class StRiNgUtIlS:
    @staticmethod
    def clean_text(text):
        return re.sub(r'\s+', ' ', text).strip()

class BaTcHPrOcEsS:
    def __init__(self, items, batch_size=10):
        self.items = items
        self.batch_size = batch_size

    def get_batches(self):
        for i in range(0, len(self.items), self.batch_size):
            yield self.items[i:i + self.batch_size]

class RePoRtGeNeRaToR:
    def __init__(self, results):
        self.results = results

    def generate_html_report(self):
        html = "<html><body><h1>ScAn RePoRt</h1><table border='1'>"
        for res in self.results:
            html += f"<tr><td>{res['url']}</td><td>{res['score']}</td></tr>"
        html += "</table></body></html>"
        return html

class GaTeS_DoRkEr:
    def __init__(self, max_workers=200, timeout=10):
        self.user_agents = USER_AGENTS
        self.processed_urls = set()
        self.displayed_domains = set()
        self.lock = threading.Lock()
        self.url_queue = queue.PriorityQueue()
        self.total_found = 0
        self.scanned_urls = 0
        self.max_workers = max_workers
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
        adapter = requests.adapters.HTTPAdapter(pool_connections=max_workers, pool_maxsize=max_workers)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        self.results = []
        self.is_running = False
        self.stats = {
            'engines': {},
            'gateways': {},
            'errors': 0
        }
        self.cache_manager = CaChEMaNaGeR()
        self.rate_limiter = RaTeLiMiTeR(10)

    def get_agent(self):
        return random.choice(self.user_agents)

    def fetch_content(self, url, referer=None):
        try:
            cached = self.cache_manager.get(url)
            if cached:
                return cached
            
            self.rate_limiter.wait()
            
            headers = {
                'User-Agent': self.get_agent(),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate, br',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
                'Cache-Control': 'max-age=0'
            }
            if referer:
                headers['Referer'] = referer
            
            res = self.session.get(url, headers=headers, timeout=self.timeout, allow_redirects=True)
            if res.status_code == 200:
                self.cache_manager.set(url, res.text)
                return res.text
        except Exception:
            with self.lock:
                self.stats['errors'] += 1
        return None

    def search_engine_query(self, engine, query, page):
        links = set()
        query_encoded = quote_plus(query)
        search_urls = {
            'google': f"https://www.google.com/search?q={query_encoded}&start={page*10}&num=100",
            'bing': f"https://www.bing.com/search?q={query_encoded}&first={page*10+1}",
            'duck': f"https://html.duckduckgo.com/html/?q={query_encoded}&s={page*50}",
            'yahoo': f"https://search.yahoo.com/search?p={query_encoded}&b={page*10+1}",
            'ask': f"https://www.ask.com/web?q={query_encoded}&page={page+1}",
            'yandex': f"https://yandex.com/search/?text={query_encoded}&p={page}",
            'baidu': f"https://www.baidu.com/s?wd={query_encoded}&pn={page*10}",
            'ecosia': f"https://www.ecosia.org/search?q={query_encoded}&p={page}",
            'qwant': f"https://www.qwant.com/?q={query_encoded}&s={page}&t=web",
            'sogou': f"https://www.sogou.com/web?query={query_encoded}&page={page+1}",
            'startpage': f"https://www.startpage.com/do/search?query={query_encoded}&startat={page*10}",
            'swisscows': f"https://swisscows.com/web?query={query_encoded}&offset={page*10}",
            'brave': f"https://search.brave.com/search?q={query_encoded}&offset={page}",
            'dogpile': f"https://www.dogpile.com/serp?q={query_encoded}&page={page+1}",
            'gibiru': f"https://gibiru.com/results.html?q={query_encoded}&p={page+1}",
            'metager': f"https://metager.org/meta/meta.ger3?eingabe={query_encoded}&page={page+1}",
            'mojeek': f"https://www.mojeek.com/search?q={query_encoded}&s={page*10+1}",
            'exalead': f"https://www.exalead.com/search/web/results/?q={query_encoded}&start_index={page*10}",
            'gigablast': f"https://www.gigablast.com/search?q={query_encoded}&n={page*10}",
            'searx': f"https://searx.be/search?q={query_encoded}&pageno={page+1}"
        }
        
        url = search_urls.get(engine)
        if not url: return []

        html = self.fetch_content(url, referer=f"https://{engine}.com/")
        if not html: return []

        soup = BeautifulSoup(html, 'html.parser')
        for a in soup.find_all('a', href=True):
            href = a.get('href')
            if href:
                if 'url?q=' in href:
                    href = href.split('url?q=')[1].split('&')[0]
                
                if href.startswith('http') and not any(d in href for d in [engine, 'google', 'bing', 'yahoo', 'yandex', 'baidu', 'ask', 'ecosia', 'qwant', 'sogou', 'startpage', 'swisscows', 'brave', 'dogpile', 'gibiru', 'metager', 'mojeek', 'exalead', 'gigablast', 'searx']):
                    links.add(href)
        
        with self.lock:
            self.stats['engines'][engine] = self.stats['engines'].get(engine, 0) + len(links)
            
        return list(links)

    def quantum_search(self, query, depth=50):
        engines = ['google', 'bing', 'duck', 'yahoo', 'ask', 'yandex', 'baidu', 'ecosia', 'qwant', 'sogou']
        
        total_requests = depth * len(engines)
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = []
            for page in range(depth):
                for eng in engines:
                    if not self.is_running:
                        break
                    futures.append(executor.submit(self.search_engine_query, eng, query, page))
            
            for future in concurrent.futures.as_completed(futures):
                if not self.is_running:
                    break
                try:
                    results = future.result(timeout=30)
                    for link in results:
                        with self.lock:
                            if link not in self.processed_urls:
                                self.processed_urls.add(link)
                                self.url_queue.put((2, link))
                except Exception:
                    continue

    def calculate_score(self, html_content):
        if not html_content: return 0
        content = html_content.lower()
        score = 0
        
        high_priority = ['checkout', 'cart', 'payment', 'billing', 'shipping', 'order', 'purchase', 'pay now', 'complete order']
        medium_priority = ['visa', 'mastercard', 'amex', 'discover', 'paypal', 'stripe', 'apple pay', 'google pay', 'bitcoin', 'crypto']
        low_priority = ['shop', 'product', 'price', 'buy', '$', '€', '£', 'total', 'subtotal', 'tax', 'discount', 'coupon']
        
        score += sum(10 for word in high_priority if word in content)
        score += sum(5 for word in medium_priority if word in content)
        score += sum(2 for word in low_priority if word in content)
        
        for keyword in EXTENDED_KEYWORDS:
            if keyword in content:
                score += 1
                
        return score

    def extract_metadata(self, soup, url):
        metadata = {
            'title': '',
            'description': '',
            'generator': '',
            'emails': [],
            'phones': []
        }
        try:
            if soup.title:
                metadata['title'] = soup.title.string.strip() if soup.title.string else ''
            
            desc = soup.find('meta', attrs={'name': 'description'})
            if desc:
                metadata['description'] = desc.get('content', '').strip()
                
            gen = soup.find('meta', attrs={'name': 'generator'})
            if gen:
                metadata['generator'] = gen.get('content', '').strip()
            
            text = soup.get_text()
            metadata['emails'] = list(set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text)))[:5]
            metadata['phones'] = list(set(re.findall(r'\+?\d{1,4}?[-.\s]?\(?\d{1,3}?\)?[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,9}', text)))[:5]
        except Exception:
            pass
        return metadata

    def verify_payment_gateway(self, url):
        domain = urlparse(url).netloc
        if not domain or any(d in domain for d in ['google', 'facebook', 'twitter', 'instagram', 'linkedin', 'youtube', 'pinterest', 'microsoft', 'github', 'apple', 'amazon', 'wikipedia', 'wordpress', 'blogspot']): 
            return

        with self.lock:
            if domain in self.displayed_domains: 
                return
            self.scanned_urls += 1

        html = self.fetch_content(url)
        if not html: 
            return

        score = self.calculate_score(html)
        if score < 10: 
            return

        found_gateways = set()
        content_lower = html.lower()
        for gateway in GATEWAYS:
            if gateway.lower() in content_lower:
                found_gateways.add(gateway)

        soup = BeautifulSoup(html, 'html.parser')
        for script in soup.find_all('script', src=True):
            src = script.get('src', '').lower()
            for gateway in GATEWAYS:
                if gateway.lower() in src:
                    found_gateways.add(gateway)
        
        for img in soup.find_all('img', src=True):
            src = img.get('src', '').lower()
            alt = img.get('alt', '').lower()
            for gateway in GATEWAYS:
                if gateway.lower() in src or gateway.lower() in alt:
                    found_gateways.add(gateway)

        has_donate_keyword = any(kw in content_lower for kw in DONATE_KEYWORDS)

        if found_gateways and has_donate_keyword:
            metadata = self.extract_metadata(soup, url)
            with self.lock:
                if domain not in self.displayed_domains:
                    self.displayed_domains.add(domain)
                    gate_str = ", ".join(found_gateways)
                    
                    result_entry = {
                        'url': url,
                        'domain': domain,
                        'gateways': list(found_gateways),
                        'score': score,
                        'metadata': metadata,
                        'timestamp': datetime.now().isoformat()
                    }
                    self.results.append(result_entry)
                    self.total_found += 1
                    
                    for gate in found_gateways:
                        self.stats['gateways'][gate] = self.stats['gateways'].get(gate, 0) + 1

        for a in soup.find_all('a', href=True):
            href = a.get('href')
            if href and not href.startswith(('javascript:', '#', 'mailto:', 'tel:')):
                new_url = urljoin(url, href)
                new_domain = urlparse(new_url).netloc
                
                if new_domain == domain:
                    with self.lock:
                        if new_url not in self.processed_urls and len(self.processed_urls) < 100000:
                            self.processed_urls.add(new_url)
                            priority = 1 if any(x in new_url.lower() for x in ['checkout', 'pay', 'cart', 'billing', 'order', 'donate']) else 3
                            self.url_queue.put((priority, new_url))

    def worker(self):
        while self.is_running:
            try:
                priority, url = self.url_queue.get(timeout=5)
                self.verify_payment_gateway(url)
                self.url_queue.task_done()
            except queue.Empty:
                break
            except Exception:
                continue

    def run_dork(self, dork, limit):
        self.is_running = True
        self.processed_urls.clear()
        self.displayed_domains.clear()
        self.total_found = 0
        self.scanned_urls = 0
        self.results.clear()
        
        search_thread = threading.Thread(target=self.quantum_search, args=(dork, 20))
        search_thread.daemon = True
        search_thread.start()
        
        time.sleep(2)

        worker_threads = []
        for _ in range(min(self.max_workers, 50)):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
            worker_threads.append(t)

        search_thread.join(timeout=60)
        
        while not self.url_queue.empty() and len(self.results) < limit:
            time.sleep(0.5)

        self.is_running = False
        
        for t in worker_threads:
            t.join(timeout=1)

        return self.results[:limit]

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta name="description" content="DoRk SeaRcH GaTeS weBsiTe - BY: @ZeRoxoN">
    <title>GaTeS DoRkEr - @ZeRoxoN</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        
        .container {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            padding: 50px;
            max-width: 600px;
            width: 100%;
            animation: slideIn 0.6s ease-out;
        }
        
        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .header {
            text-align: center;
            margin-bottom: 40px;
        }
        
        .title {
            font-size: 48px;
            font-weight: 900;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 10px;
            letter-spacing: 2px;
        }
        
        .subtitle {
            color: #666;
            font-size: 14px;
            letter-spacing: 3px;
            text-transform: uppercase;
        }
        
        .bio {
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            color: white;
            padding: 20px;
            border-radius: 15px;
            margin-bottom: 30px;
            text-align: center;
            font-size: 13px;
            line-height: 1.6;
        }
        
        .bio-image {
            width: 80px;
            height: 80px;
            border-radius: 50%;
            background: rgba(255, 255, 255, 0.2);
            margin: 0 auto 15px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 40px;
        }
        
        .bio-text {
            font-weight: 500;
        }
        
        .options {
            display: flex;
            gap: 15px;
            margin-bottom: 30px;
        }
        
        .option {
            flex: 1;
        }
        
        .option input[type="radio"] {
            display: none;
        }
        
        .option label {
            display: block;
            padding: 20px;
            border: 3px solid #e0e0e0;
            border-radius: 15px;
            text-align: center;
            cursor: pointer;
            transition: all 0.3s ease;
            font-weight: 600;
            font-size: 14px;
            letter-spacing: 1px;
        }
        
        .option input[type="radio"]:checked + label {
            border-color: #667eea;
            background: linear-gradient(135deg, rgba(102, 126, 234, 0.1) 0%, rgba(118, 75, 162, 0.1) 100%);
            color: #667eea;
            transform: scale(1.05);
        }
        
        .option label:hover {
            border-color: #667eea;
            transform: translateY(-2px);
        }
        
        .input-group {
            margin-bottom: 25px;
        }
        
        .input-group label {
            display: block;
            margin-bottom: 10px;
            color: #333;
            font-weight: 600;
            font-size: 14px;
            letter-spacing: 1px;
        }
        
        .input-group input {
            width: 100%;
            padding: 15px;
            border: 2px solid #e0e0e0;
            border-radius: 10px;
            font-size: 14px;
            transition: all 0.3s ease;
        }
        
        .input-group input:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        
        .button-group {
            display: flex;
            gap: 15px;
        }
        
        button {
            flex: 1;
            padding: 15px;
            border: none;
            border-radius: 10px;
            font-weight: 700;
            font-size: 14px;
            letter-spacing: 2px;
            cursor: pointer;
            transition: all 0.3s ease;
            text-transform: uppercase;
        }
        
        .btn-go {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            box-shadow: 0 10px 25px rgba(102, 126, 234, 0.3);
        }
        
        .btn-go:hover:not(:disabled) {
            transform: translateY(-3px);
            box-shadow: 0 15px 35px rgba(102, 126, 234, 0.4);
        }
        
        .btn-go:disabled {
            opacity: 0.6;
            cursor: not-allowed;
        }
        
        .btn-clear {
            background: #f0f0f0;
            color: #333;
        }
        
        .btn-clear:hover {
            background: #e0e0e0;
        }
        
        .results-container {
            margin-top: 40px;
            max-height: 500px;
            overflow-y: auto;
            border-top: 2px solid #e0e0e0;
            padding-top: 20px;
        }
        
        .result-item {
            background: #f9f9f9;
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 15px;
            border-left: 4px solid #667eea;
            animation: fadeIn 0.3s ease;
        }
        
        @keyframes fadeIn {
            from {
                opacity: 0;
                transform: translateX(-10px);
            }
            to {
                opacity: 1;
                transform: translateX(0);
            }
        }
        
        .result-url {
            color: #667eea;
            font-weight: 600;
            word-break: break-all;
            font-size: 12px;
            margin-bottom: 8px;
        }
        
        .result-gateways {
            color: #764ba2;
            font-size: 12px;
            font-weight: 500;
        }
        
        .result-score {
            color: #999;
            font-size: 11px;
            margin-top: 5px;
        }
        
        .loading {
            text-align: center;
            color: #667eea;
            font-weight: 600;
            margin: 20px 0;
        }
        
        .spinner {
            border: 3px solid #f0f0f0;
            border-top: 3px solid #667eea;
            border-radius: 50%;
            width: 30px;
            height: 30px;
            animation: spin 1s linear infinite;
            margin: 0 auto 10px;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .stats {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 15px;
            border-radius: 10px;
            text-align: center;
            margin-top: 20px;
            font-size: 13px;
        }
        
        .stats-item {
            display: inline-block;
            margin: 0 15px;
        }
        
        .stats-number {
            font-weight: 700;
            font-size: 16px;
        }
        
        .error-message {
            background: #fee;
            color: #c33;
            padding: 15px;
            border-radius: 10px;
            margin-top: 20px;
            border-left: 4px solid #c33;
        }
        
        .success-message {
            background: #efe;
            color: #3c3;
            padding: 15px;
            border-radius: 10px;
            margin-top: 20px;
            border-left: 4px solid #3c3;
        }
        
        ::-webkit-scrollbar {
            width: 8px;
        }
        
        ::-webkit-scrollbar-track {
            background: #f0f0f0;
            border-radius: 10px;
        }
        
        ::-webkit-scrollbar-thumb {
            background: #667eea;
            border-radius: 10px;
        }
        
        ::-webkit-scrollbar-thumb:hover {
            background: #764ba2;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="title">GaTeS DoRkEr</div>
            <div class="subtitle">@ZeRoxoN</div>
        </div>
        
        <div class="bio">
            <div class="bio-image">🔍</div>
            <div class="bio-text">Advanced Payment Gateway Hunter | Google Dorking Tool | Multi-Engine Search</div>
        </div>
        
        <div class="options">
            <div class="option">
                <input type="radio" id="paypal" name="gateway" value="paypal" checked>
                <label for="paypal">GaTeS PaYpAL dONaTe</label>
            </div>
            <div class="option">
                <input type="radio" id="braintree" name="gateway" value="braintree">
                <label for="braintree">GaTeS BRaIntRee dONaTe</label>
            </div>
        </div>
        
        <div class="input-group">
            <label for="limit">NuMbEr Of GaTeS (10 - 90000)</label>
            <input type="number" id="limit" min="10" max="90000" value="100" placeholder="Enter number of gateways to find">
        </div>
        
        <div class="button-group">
            <button class="btn-go" id="goBtn" onclick="startScan()">Go</button>
            <button class="btn-clear" onclick="clearResults()">CLeAr</button>
        </div>
        
        <div id="statusContainer"></div>
        <div id="resultsContainer" class="results-container"></div>
    </div>
    
    <script>
        let isScanning = false;
        
        function startScan() {
            const gateway = document.querySelector('input[name="gateway"]:checked').value;
            const limit = parseInt(document.getElementById('limit').value);
            
            if (limit < 10 || limit > 90000) {
                showError('NuMbEr MuSt Be BeTeWeEn 10 AnD 90000');
                return;
            }
            
            if (isScanning) return;
            
            isScanning = true;
            document.getElementById('goBtn').disabled = true;
            
            const statusContainer = document.getElementById('statusContainer');
            statusContainer.innerHTML = '<div class="loading"><div class="spinner"></div>ScAnNiNg FoR ' + gateway.toUpperCase() + ' GaTeWaYs...</div>';
            
            const resultsContainer = document.getElementById('resultsContainer');
            resultsContainer.innerHTML = '';
            
            fetch('/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    gateway: gateway,
                    limit: limit
                })
            })
            .then(response => response.json())
            .then(data => {
                isScanning = false;
                document.getElementById('goBtn').disabled = false;
                
                if (data.error) {
                    showError(data.error);
                } else {
                    displayResults(data.results, data.total_found, data.scanned_urls);
                }
                
                statusContainer.innerHTML = '';
            })
            .catch(error => {
                isScanning = false;
                document.getElementById('goBtn').disabled = false;
                showError('ErRoR: ' + error.message);
                statusContainer.innerHTML = '';
            });
        }
        
        function displayResults(results, totalFound, scannedUrls) {
            const resultsContainer = document.getElementById('resultsContainer');
            
            if (results.length === 0) {
                resultsContainer.innerHTML = '<div class="error-message">No GaTeWaYs FoUnD</div>';
                return;
            }
            
            let html = '<div class="stats">';
            html += '<div class="stats-item">FoUnD: <span class="stats-number">' + totalFound + '</span></div>';
            html += '<div class="stats-item">ScAnNeD: <span class="stats-number">' + scannedUrls + '</span></div>';
            html += '</div>';
            
            results.forEach(result => {
                html += '<div class="result-item">';
                html += '<div class="result-url"><a href="' + result.url + '" target="_blank" style="color: #667eea; text-decoration: none;">' + result.url + '</a></div>';
                html += '<div class="result-gateways">GaTeWaYs: ' + result.gateways.join(', ') + '</div>';
                html += '<div class="result-score">ScOrE: ' + result.score + ' | DoMaIn: ' + result.domain + '</div>';
                html += '</div>';
            });
            
            resultsContainer.innerHTML = html;
        }
        
        function showError(message) {
            const resultsContainer = document.getElementById('resultsContainer');
            resultsContainer.innerHTML = '<div class="error-message">' + message + '</div>';
        }
        
        function clearResults() {
            document.getElementById('resultsContainer').innerHTML = '';
            document.getElementById('statusContainer').innerHTML = '';
            document.getElementById('limit').value = '100';
        }
    </script>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/scan', methods=['POST'])
def scan():
    try:
        data = request.get_json()
        gateway_type = data.get('gateway', 'paypal')
        limit = min(int(data.get('limit', 100)), 90000)
        limit = max(limit, 10)
        
        dorks = PAYPAL_DORKS if gateway_type == 'paypal' else BRAINTREE_DORKS
        
        dorker = GaTeS_DoRkEr(max_workers=100, timeout=8)
        
        all_results = []
        for dork in dorks:
            if len(all_results) >= limit:
                break
            results = dorker.run_dork(dork, limit - len(all_results))
            all_results.extend(results)
        
        return jsonify({
            'results': all_results[:limit],
            'total_found': dorker.total_found,
            'scanned_urls': dorker.scanned_urls,
            'error': None
        })
    except Exception as e:
        return jsonify({
            'results': [],
            'total_found': 0,
            'scanned_urls': 0,
            'error': str(e)
        })

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000, threaded=True)
