import requests
import argparse
import sys
import math
from collections import Counter
from urllib.parse import urljoin

def parse_args():
    parser = argparse.ArgumentParser(description="Broken Authentication Checker")
    parser.add_argument("url", help="Target URL to analyze (e.g., login page)")
    parser.add_argument("--login-url", help="Login endpoint URL (optional, for session fixation test)")
    parser.add_argument("--username", help="Test username for login (optional)")
    parser.add_argument("--password", help="Test password for login (optional)")
    return parser.parse_args()

def check_cookie_security(cookies):
    results = []
    for cookie in cookies:
        name = cookie.name
        flags = []
        if cookie.get_nonstandard_attr('HttpOnly'):
            flags.append("HttpOnly")
        if cookie.secure:
            flags.append("Secure")
        samesite = cookie.get_nonstandard_attr('SameSite')
        if samesite:
            flags.append(f"SameSite={samesite}")
        
        issues = []
        if not cookie.get_nonstandard_attr('HttpOnly'):
            issues.append("Missing HttpOnly flag")
        if not cookie.secure:
            issues.append("Missing Secure flag")
        if not samesite:
            issues.append("Missing SameSite attribute")
        
        results.append({
            'name': name,
            'flags': flags or ["None"],
            'issues': issues or ["None"]
        })
    return results

def calculate_entropy(token):
    if not token:
        return 0
    char_counts = Counter(token)
    length = len(token)
    entropy = 0
    for count in char_counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy

def test_session_fixation(url, login_url, username, password):
    session = requests.Session()
    try:
        # Step 1: Get initial session ID
        pre_login_response = session.get(url, timeout=5)
        pre_login_cookies = session.cookies.get_dict()
        pre_login_session_id = pre_login_cookies.get('session') or pre_login_cookies.get('PHPSESSID')
        
        if not pre_login_session_id:
            return {"status": "Skipped", "reason": "No session cookie found before login"}

        # Step 2: Attempt login
        login_data = {'username': username, 'password': password}
        login_response = session.post(login_url, data=login_data, timeout=5)
        post_login_cookies = session.cookies.get_dict()
        post_login_session_id = post_login_cookies.get('session') or post_login_cookies.get('PHPSESSID')

        # Step 3: Check if session ID changed
        if pre_login_session_id == post_login_session_id:
            return {"status": "Vulnerable", "details": "Session ID did not change after login (possible session fixation)"}
        return {"status": "Secure", "details": "Session ID changed after login"}
    except requests.RequestException as e:
        return {"status": "Error", "reason": f"Failed to test session fixation: {e}"}

def main():
    args = parse_args()
    url = args.url
    print(f"Analyzing authentication for {url}...")

    # Step 1: Fetch cookies
    try:
        response = requests.get(url, timeout=5)
        cookies = response.cookies
    except requests.RequestException as e:
        print(f"Error fetching {url}: {e}")
        sys.exit(1)

    # Step 2: Analyze cookie security
    print("\n=== Cookie Security Analysis ===")
    if not cookies:
        print("No cookies found.")
    else:
        cookie_results = check_cookie_security(cookies)
        for result in cookie_results:
            print(f"Cookie: {result['name']}")
            print(f"Flags: {', '.join(result['flags'])}")
            print(f"Issues: {', '.join(result['issues'])}")
            print()

    # Step 3: Analyze token entropy
    print("\n=== Token Entropy Analysis ===")
    session_cookie = cookies.get('session') or cookies.get('PHPSESSID')
    if session_cookie:
        entropy = calculate_entropy(session_cookie)
        print(f"Session Token: {session_cookie[:10]}... (truncated)")
        print(f"Entropy: {entropy:.2f} bits")
        if entropy < 50:
            print("Warning: Low entropy detected (potentially predictable token)")
        else:
            print("Entropy appears sufficient")
    else:
        print("No session token found for entropy analysis")

    # Step 4: Test session fixation (if login details provided)
    if args.login_url and args.username and args.password:
        print("\n=== Session Fixation Test ===")
        fixation_result = test_session_fixation(url, args.login_url, args.username, args.password)
        print(f"Status: {fixation_result['status']}")
        print(f"Details: {fixation_result['details']}")
    else:
        print("\n=== Session Fixation Test ===")
        print("Skipped: Provide --login-url, --username, and --password to test session fixation")

    print("\nAnalysis completed.")

if __name__ == "__main__":
    main()
