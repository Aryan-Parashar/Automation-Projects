import time
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse

# 2CAPTCHA API key
API_KEY = '2captcha_api_key'

# URL of the website you want to bypass CAPTCHA
TARGET_URL = 'https://example.com/login'

# Session object to maintain cookies and headers
session = requests.Session()

def solve_captcha(api_key, site_key, url):
    """Solve CAPTCHA using 2Captcha service."""
    captcha_request_url = 'https://2captcha.com/in.php'
    
    captcha_request_payload = {
        'key': api_key,
        'method': 'userrecaptcha',
        'googlekey': site_key,
        'pageurl': url,
        'json': 1
    }
    response = requests.post(captcha_request_url, data=captcha_request_payload)
    request_id = response.json().get('request')
    if response.json().get('status') != 1:
        print(f"Error submitting CAPTCHA: {response.json().get('request')}")
        return None
    
    captcha_result_url = f'https://2captcha.com/res.php?key={api_key}&action=get&id={request_id}&json=1'
    while True:
        result = requests.get(captcha_result_url).json()
        if result.get('status') == 1:
            print(f"CAPTCHA Solved: {result.get('request')}")
            return result.get('request')
        elif result.get('request') == 'CAPCHA_NOT_READY':
            print("CAPTCHA not ready yet, retrying...")
        else:
            print(f"Error retrieving CAPTCHA solution: {result.get('request')}")
            return None
        time.sleep(5)  # Wait for a few seconds before checking again

def bypass_captcha(session, target_url):
    """Bypass CAPTCHA by solving and submitting the CAPTCHA token."""
    # Ensure target_url is properly formatted
    if not urlparse(target_url).scheme:
        target_url = f'https://{target_url}'
    
    response = session.get(target_url)
    soup = BeautifulSoup(response.content, 'html.parser')

    # Find CAPTCHA site key
    site_key_element = soup.find('div', {'class': 'g-recaptcha'})
    if site_key_element:
        site_key = site_key_element['data-sitekey']
        captcha_token = solve_captcha(API_KEY, site_key, target_url)
        
        if not captcha_token:
            print("Failed to solve CAPTCHA.")
            return

        # Extract other form fields
        form = soup.find('form')  # Find the form on the page
        if not form:
            print("No form found on the page.")
            return
        
        form_action = form['action']
        form_method = form.get('method', 'post').lower()
        form_fields = {field.get('name'): field.get('value', '') for field in form.find_all('input') if field.get('name')}
        
        # Add CAPTCHA response to the form fields
        form_fields['g-recaptcha-response'] = captcha_token
        
        # Submit the form
        form_url = form_action if form_action.startswith('https') else target_url + form_action
        if form_method == 'post':
            response = session.post(form_url, data=form_fields)
        else:
            response = session.get(form_url, params=form_fields)
        
        if response.status_code == 200:
            print(f'CAPTCHA bypassed and form submitted successfully for {target_url}')
        else:
            print(f'Failed to submit form for {target_url}. Status code: {response.status_code}')
        time.sleep(2)
    else:
        print(f'No CAPTCHA found on {target_url}')

# Main function to orchestrate CAPTCHA solving and bypassing
def main():
    # Use session to handle cookies and headers
    bypass_captcha(session, TARGET_URL)

if __name__ == '__main__':
    main()
