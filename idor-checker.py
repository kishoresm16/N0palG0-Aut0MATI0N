import requests
from bs4 import BeautifulSoup
import argparse
import sys
import json
from urllib.parse import urljoin, urlparse, parse_qs
import re

def parse_args():
    parser = argparse.ArgumentParser(description="Professional IDOR Vulnerability Scanner")
    parser.add_argument("url", help="Target URL to scan for IDOR vulnerabilities")
    parser.add_argument("--login-url", help="Login endpoint URL for authenticated testing")
    parser.add_argument("--username", help="Test username for login")
    parser.add_argument("--password", help="Test password for login")
    parser.add_argument("--second-username", help="Second username for horizontal testing")
    parser.add_argument("--second-password", help="Second password for horizontal testing")
    parser.add_argument("--output", choices=["json", "text"], default="text", help="Output format (text or json)")
    return parser.parse_args()

def login(login_url, username, password):
    try:
        session = requests.Session()
        data = {"username": username, "password": password}
        response = session.post(login_url, data=data, timeout=5)
        if response.status_code == 200 and "login failed" not in response.text.lower():
            return session
        print(f"Login failed for {username}")
        return None
    except requests.RequestException as e:
        print(f"Error logging in: {e}")
        return None

def find_idor_parameters(url, session=None):
    try:
        response = (session or requests).get(url, timeout=5)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Find forms
        forms = []
        for form in soup.find_all('form'):
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            inputs = [inp.get('name') for inp in form.find_all('input') if inp.get('name')]
            forms.append({
                'action': urljoin(url, action) if action else url,
                'method': method,
                'inputs': inputs
            })

        # Find URL parameters
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        param_names = [name for name in params.keys() if re.match(r'^(id|uid|user_id|pid|account|file|.*_id)$', name, re.I)]

        # Find API-like endpoints in JavaScript or links
        api_endpoints = []
        for script in soup.find_all('script'):
            if script.string:
                urls = re.findall(r'https?://[^\s"\']+|\b/?api/[^\s"\']+', script.string)
                api_endpoints.extend(urljoin(url, u) for u in urls)
        for link in soup.find_all('a', href=True):
            if 'api' in link['href'].lower():
                api_endpoints.append(urljoin(url, link['href']))

        return forms, param_names, api_endpoints
    except requests.RequestException as e:
        print(f"Error fetching {url}: {e}")
        return [], [], []

def test_idor(url, forms, param_names, api_endpoints, session, second_session=None):
    vulnerabilities = []
    
    # Test forms
    for form in forms:
        action = form['action']
        method = form['method']
        inputs = [name for name in form['inputs'] if re.match(r'^(id|uid|user_id|pid|account|file|.*_id)$', name, re.I)]
        
        for input_name in inputs:
            for value in [1, 2, "admin", "123"]:  # Test common values
                payload = {input_name: value}
                try:
                    if method == 'post':
                        response = session.post(action, data=payload, timeout=5)
                        if second_session:
                            second_response = second_session.post(action, data=payload, timeout=5)
                    else:
                        response = session.get(action, params=payload, timeout=5)
                        if second_session:
                            second_response = second_session.get(action, params=payload, timeout=5)
                    
                    if response.status_code == 200:
                        if second_session and response.text == second_response.text:
                            vulnerabilities.append({
                                'endpoint': action,
                                'type': f'Form Input: {input_name}',
                                'value': value,
                                'details': f"Same response for different users at {action} (Status: {response.status_code})"
                            })
                        elif "unauthorized" not in response.text.lower():
                            vulnerabilities.append({
                                'endpoint': action,
                                'type': f'Form Input: {input_name}',
                                'value': value,
                                'details': f"Potential IDOR at {action} with {input_name}={value} (Status: {response.status_code})"
                            })
                except requests.RequestException as e:
                    print(f"Error testing form at {action}: {e}")

    # Test URL parameters
    if param_names:
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        for param in param_names:
            for value in [1, 2, "admin", "123"]:
                params = {param: value}
                try:
                    response = session.get(base_url, params=params, timeout=5)
                    if second_session:
                        second_response = second_session.get(base_url, params=params, timeout=5)
                    
                    if response.status_code == 200:
                        if second_session and response.text == second_response.text:
                            vulnerabilities.append({
                                'endpoint': base_url,
                                'type': f'Parameter: {param}',
                                'value': value,
                                'details': f"Same response for different users for {param}={value} (Status: {response.status_code})"
                            })
                        elif "unauthorized" not in response.text.lower():
                            vulnerabilities.append({
                                'endpoint': base_url,
                                'type': f'Parameter: {param}',
                                'value': value,
                                'details': f"Potential IDOR for {param}={value} (Status: {response.status_code})"
                            })
                except requests.RequestException as e:
                    print(f"Error testing parameter {param}: {e}")

    # Test API endpoints
    for endpoint in api_endpoints:
        for value in [1, 2, "admin", "123"]:
            params = {"id": value}  # Common ID parameter for APIs
            try:
                response = session.get(endpoint, params=params, timeout=5)
                if second_session:
                    second_response = second_session.get(endpoint, params=params, timeout=5)
                
                if response.status_code == 200:
                    if second_session and response.text == second_response.text:
                        vulnerabilities.append({
                            'endpoint': endpoint,
                            'type': 'API Parameter: id',
                            'value': value,
                            'details': f"Same response for different users at {endpoint} (Status: {response.status_code})"
                        })
                    elif "unauthorized" not in response.text.lower():
                        vulnerabilities.append({
                            'endpoint': endpoint,
                            'type': 'API Parameter: id',
                            'value': value,
                            'details': f"Potential IDOR at {endpoint} with id={value} (Status: {response.status_code})"
                        })
            except requests.RequestException as e:
                print(f"Error testing API endpoint {endpoint}: {e}")

    return vulnerabilities

def main():
    args = parse_args()
    url = args.url
    print(f"Scanning {url} for IDOR vulnerabilities...")

    # Login with primary account
    session = login(args.login_url, args.username, args.password) if args.login_url and args.username and args.password else requests.Session()
    if args.login_url and not session:
        print("Primary login failed. Exiting.")
        return

    # Login with second account for horizontal testing
    second_session = None
    if args.second_username and args.second_password and args.login_url:
        second_session = login(args.login_url, args.second_username, args.second_password)
        if not second_session:
            print("Second login failed. Continuing with single account.")

    # Find IDOR parameters
    forms, param_names, api_endpoints = find_idor_parameters(url, session)
    if not forms and not param_names and not api_endpoints:
        print("No forms, URL parameters, or API endpoints found.")
        return

    # Print discovered inputs
    if forms:
        print("\nForms Found:")
        for form in forms:
            print(f"- Action: {form['action']}, Method: {form['method'].upper()}, Inputs: {form['inputs']}")
    if param_names:
        print("\nURL Parameters Found:")
        print(f"- {param_names}")
    if api_endpoints:
        print("\nAPI Endpoints Found:")
        for endpoint in api_endpoints:
            print(f"- {endpoint}")

    # Test for IDOR
    vulnerabilities = test_idor(url, forms, param_names, api_endpoints, session, second_session)
    
    # Output results
    if args.output == "json":
        output = {"url": url, "vulnerabilities": vulnerabilities}
        print(json.dumps(output, indent=2))
    else:
        if vulnerabilities:
            print("\nVulnerabilities Found:")
            for vuln in vulnerabilities:
                print(f"=== Vulnerable Endpoint: {vuln['endpoint']} ===")
                print(f"Type: {vuln['type']}")
                print(f"Value: {vuln['value']}")
                print(f"Details: {vuln['details']}")
        else:
            print("\nNo IDOR vulnerabilities detected.")

    print("\nScanning completed.")

if __name__ == "__main__":
    main()
