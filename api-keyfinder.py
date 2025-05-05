import requests
import argparse
import sys
import json
import re
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from requests.exceptions import HTTPError

PI_KEY_PATTERNS = {
    "aws_key": r'AKIA[0-9A-Z]{16}',
    "google_api_key": r'AIza[0-9A-Za-z-_]{35}',
    "stripe_live_key": r'sk_live_[0-9a-zA-Z]{24}',
    "stripe_public_key": r'pk_live_[0-9a-zA-Z]{24}',
    "github_token": r'ghp_[A-Za-z0-9]{36}',
    "ssh_private_key": r'-----BEGIN (RSA|OPENSSH) PRIVATE KEY-----\n[A-Za-z0-9+/=\n]+-----END (RSA|OPENSSH) PRIVATE KEY-----',
    "heroku_api_key": r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    "mailchimp_api_key": r'[A-Za-z0-9]{32}-us[0-9]{1,2}',
    "mailgun_private_key": r'key-[A-Za-z0-9]{32}',
    "sendgrid_api_token": r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}',
    "stripe_test_key": r'sk_test_[0-9a-zA-Z]{24}',
    "stripe_restricted_key": r'rk_test_[0-9a-zA-Z]{24}',
    "square_access_token": r'sq0atp-[0-9A-Za-z\-_]{22}',
    "square_oauth_secret": r'sq0csp-[0-9A-Za-z\-_]{43}',
    "twilio_account_sid": r'AC[a-zA-Z0-9]{32}',
    "twilio_api_key": r'SK[a-zA-Z0-9]{32}',
    "slack_token": r'xox[baprs]-([0-9a-zA-Z]{10,48})?',
    "slack_webhook": r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}',
    "generic_api_key": r'[0-9a-f]{32}-us[0-9]{1,2}',
    "google_cloud_service_account": r'\"type\": \"service_account\"',
    "google_oauth_access_token": r'ya29\.[0-9A-Za-z\-_]+',
    "google_oauth_client_id": r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
    "google_api_key_alt": r'[A-Za-z0-9_]{21}--[A-Za-z0-9_]{8}',
    "google_recaptcha_key": r'6L[0-9A-Za-z-_]{38}',
    "stripe_secret_key": r'sk_live_[0-9a-z]{32}',
    "stripe_publishable_key": r'pk_live_[0-9a-z]{32}',
    "azure_key": r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    "zapier_webhook": r'https://hooks\.zapier\.com/hooks/catch/[A-Za-z0-9]+/[A-Za-z0-9]+/',
    "slack_oauth": r'xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}',
    "slack_webhook_alt": r'T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}',
    "stripe_test_secret_key": r'sk_test_[0-9a-z]{32}',
    "stripe_restricted_key_alt": r'rk_live_[0-9a-z]{32}',
    "mailchimp_api_key_alt": r'[0-9a-f]{32}-us[0-9]{1,2}',
    "mailgun_api_key": r'key-[0-9a-zA-Z]{32}',
    "generic_uuid": r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    "paypal_access_token": r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
    "square_oauth_secret_alt": r'sq0csp-[0-9A-Za-z\-_]{43}',
    "firebase_cloud_messaging": r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
    "amazon_mws_auth_token": r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    "facebook_access_token": r'[A-Za-z0-9]{125}',
    "facebook_oauth": r'EAACEdEose0cBA[0-9A-Za-z]+',
    "telegram_bot_api_token": r'[0-9]{15}:[0-9A-Za-z_]{32}',
    "twitter_access_token": r'[1-9][0-9]+-[0-9a-zA-Z]{24}',
    "twilio_api_key_alt": r'SK[0-9a-fA-F]{32}',
    "generic_secret": r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
}

def parse_args():
    parser = argparse.ArgumentParser(description="API Key Scanner for .js Files")
    parser.add_argument("-d", "--domain", help="Single domain to check (e.g., example.com)")
    parser.add_argument("-D", "--domain-list", help="File containing list of subdomains (one per line)")
    parser.add_argument("--output", choices=["text", "json"], default="text", help="Output format (text or json)")
    return parser.parse_args()

def find_js_files(url, visited=None, max_depth=2, depth=0):
    if visited is None:
        visited = set()
    if depth > max_depth or url in visited:
        return set()
    
    js_files = set()
    try:
        if not url.startswith(('http://', 'https://')):
            url = f"https://{url}"
        response = requests.get(url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
        response.raise_for_status()
        visited.add(url)

        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Find <script> tags with src attributes
        for script in soup.find_all('script', src=True):
            src = script['src']
            if src.endswith('.js'):
                js_url = urljoin(url, src)
                js_files.add(js_url)
        
        # Find links to other pages (for recursive crawling)
        for link in soup.find_all('a', href=True):
            href = urljoin(url, link['href'])
            if urlparse(href).netloc == urlparse(url).netloc and href not in visited:
                js_files.update(find_js_files(href, visited, max_depth, depth + 1))
                
    except HTTPError:
        # Suppress HTTP errors like 404
        pass
    except requests.RequestException as e:
        # Log critical errors (e.g., timeouts) to results
        js_files.add(f"error:{url}:{str(e)}")
    
    return js_files

def scan_js_file(js_url):
    findings = []
    try:
        response = requests.get(js_url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
        response.raise_for_status()
        content = response.text

        for key_type, pattern in PI_KEY_PATTERNS.items():
            matches = re.findall(pattern, content, re.MULTILINE)
            for match in matches:
                # Skip generic_uuid unless clearly an API key
                if key_type == "generic_uuid" and not any(key in content.lower() for key in ["api", "key", "token"]):
                    continue
                findings.append({
                    "type": key_type,
                    "value": match,
                    "file": js_url
                })
                
    except requests.RequestException as e:
        findings.append({
            "type": "error",
            "value": None,
            "file": js_url,
            "details": str(e)
        })
    
    return findings

def read_domains_from_file(file_path):
    try:
        with open(file_path, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: File {file_path} not found")
        sys.exit(1)
    except IOError as e:
        print(f"Error reading file {file_path}: {e}")
        sys.exit(1)

def main():
    args = parse_args()
    
    if not args.domain and not args.domain_list:
        print("Error: At least one of -d or -D is required")
        sys.exit(1)

    domains = []
    if args.domain:
        domains.append(args.domain)
    if args.domain_list:
        domains.extend(read_domains_from_file(args.domain_list))

    results = []
    for domain in domains:
        print(f"Scanning {domain} for .js files..." if args.output == "text" else "", end="")
        js_files_raw = find_js_files(domain)
        js_files = [f for f in js_files_raw if not f.startswith("error:")]
        errors = [f.split(":", 2) for f in js_files_raw if f.startswith("error:")]
        
        domain_result = {"host": domain, "js_files": list(js_files), "findings": [], "errors": []}
        for _, url, error in errors:
            domain_result["errors"].append({"url": url, "details": error})
        
        print(f"\nFound {len(js_files)} .js files for {domain}" if args.output == "text" else "", end="")
        for js_file in js_files:
            print(f"\nScanning {js_file}..." if args.output == "text" else "", end="")
            findings = scan_js_file(js_file)
            domain_result["findings"].extend(findings)
        
        results.append(domain_result)

    # Output results
    if args.output == "json":
        print(json.dumps({"results": results}, indent=2))
    else:
        for result in results:
            print(f"\n=== API Key Scan: {result['host']} ===")
            print(f"JavaScript Files Found: {len(result['js_files'])}")
            if result["js_files"]:
                print("Files:")
                for js_file in result["js_files"]:
                    print(f"- {js_file}")
            if result["findings"]:
                print("\nExposed API Keys:")
                for finding in result["findings"]:
                    if finding["type"] == "error":
                        print(f"- Error in {finding['file']}: {finding['details']}")
                    else:
                        print(f"- Type: {finding['type']}")
                        print(f"  Value: \033[91m{finding['value']}\033[0m")
                        print(f"  File: {finding['file']}")
            else:
                print("\nNo exposed API keys detected.")
            if result["errors"] and args.output == "text":
                print("\nErrors (suppressed):")
                for error in result["errors"]:
                    print(f"- {error['url']}: {error['details']}")
    
    print("\nScan completed.")

if __name__ == "__main__":
    main()
