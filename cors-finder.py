import requests
import argparse
import sys
import json
from urllib.parse import urlparse
from requests.exceptions import ConnectTimeout

def parse_args():
    parser = argparse.ArgumentParser(description="CORS Vulnerability Checker")
    parser.add_argument("-d", "--domain", help="Single domain to check (e.g., example.com)")
    parser.add_argument("-D", "--domain-list", help="File containing list of subdomains (one per line)")
    parser.add_argument("--output", choices=["text", "json"], default="text", help="Output format (text or json)")
    return parser.parse_args()

def test_cors_headers(url, domain):
    result = {"host": domain, "vulnerabilities": [], "details": {}}
    
    # Normalize URL and try HTTPS first, then HTTP on failure
    if not url.startswith(('http://', 'https://')):
        url = f"https://{url}"
    parsed_url = urlparse(url)
    base_urls = [
        f"https://{parsed_url.netloc}",
        f"http://{parsed_url.netloc}"
    ]

    # Common headers for CORS testing
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    }

    for base_url in base_urls:
        # Test 1: Simple GET request to check ACAO
        try:
            response = requests.get(base_url, headers=headers, timeout=5)
            cors_headers = {
                "Access-Control-Allow-Origin": response.headers.get("Access-Control-Allow-Origin"),
                "Access-Control-Allow-Credentials": response.headers.get("Access-Control-Allow-Credentials"),
            }
            result["details"]["simple_request"] = cors_headers

            if cors_headers["Access-Control-Allow-Origin"] == "*" and cors_headers["Access-Control-Allow-Credentials"] == "true":
                result["vulnerabilities"].append({
                    "type": "Wildcard Origin with Credentials",
                    "details": "Allow-Origin: * with Allow-Credentials: true allows any origin to access sensitive data."
                })
            elif cors_headers["Access-Control-Allow-Origin"] == "*":
                result["vulnerabilities"].append({
                    "type": "Wildcard Origin",
                    "details": "Allow-Origin: * allows any origin, potentially exposing non-sensitive data."
                })
        except ConnectTimeout:
            result["details"]["simple_request"] = {"error": f"Connection to {base_url} timed out."}
            if base_url.startswith("http://"):  # If HTTP also fails, stop
                result["vulnerabilities"].append({
                    "type": "Request Error",
                    "details": f"Failed to fetch {base_url}: Connection timed out."
                })
                return result
            continue
        except requests.RequestException as e:
            result["details"]["simple_request"] = {"error": str(e)}
            if base_url.startswith("http://"):
                result["vulnerabilities"].append({
                    "type": "Request Error",
                    "details": f"Failed to fetch {base_url}: {str(e)}"
                })
                return result
            continue

        # Test 2: Pre-flight request with arbitrary Origin
        try:
            preflight_headers = headers.copy()
            preflight_headers.update({
                "Origin": "http://malicious.com",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Content-Type"
            })
            response = requests.options(base_url, headers=preflight_headers, timeout=5)
            cors_headers = {
                "Access-Control-Allow-Origin": response.headers.get("Access-Control-Allow-Origin"),
                "Access-Control-Allow-Methods": response.headers.get("Access-Control-Allow-Methods"),
                "Access-Control-Allow-Headers": response.headers.get("Access-Control-Allow-Headers"),
                "Access-Control-Allow-Credentials": response.headers.get("Access-Control-Allow-Credentials"),
            }
            result["details"]["preflight_request"] = cors_headers

            if cors_headers["Access-Control-Allow-Origin"] == "http://malicious.com":
                result["vulnerabilities"].append({
                    "type": "Reflected Arbitrary Origin",
                    "details": "Server reflects arbitrary Origin header, allowing untrusted origins."
                })
            if cors_headers["Access-Control-Allow-Methods"] and "PUT,DELETE" in cors_headers["Access-Control-Allow-Methods"].upper():
                result["vulnerabilities"].append({
                    "type": "Permissive Methods",
                    "details": f"Allow-Methods: {cors_headers['Access-Control-Allow-Methods']} includes risky methods."
                })
        except requests.RequestException as e:
            result["details"]["preflight_request"] = {"error": str(e)}

        # Test 3: Null Origin
        try:
            null_headers = headers.copy()
            null_headers["Origin"] = "null"
            response = requests.get(base_url, headers=null_headers, timeout=5)
            cors_headers = {
                "Access-Control-Allow-Origin": response.headers.get("Access-Control-Allow-Origin"),
            }
            result["details"]["null_origin"] = cors_headers

            if cors_headers["Access-Control-Allow-Origin"] == "null":
                result["vulnerabilities"].append({
                    "type": "Null Origin Allowed",
                    "details": "Server allows Origin: null, potentially exploitable via sandboxed iframes."
                })
        except requests.RequestException as e:
            result["details"]["null_origin"] = {"error": str(e)}

        return result  # Exit after successful HTTPS or HTTP test

    return result  # Return if both HTTPS and HTTP fail

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
        print(f"Checking CORS configuration for {domain}..." if args.output == "text" else "", end="")
        result = test_cors_headers(domain, domain)
        results.append(result)

    # Output results
    if args.output == "json":
        print(json.dumps({"results": results}, indent=2))
    else:
        for result in results:
            print(f"\n=== CORS Check: {result['host']} ===")
            if result["vulnerabilities"]:
                print("Vulnerabilities Found:")
                for vuln in result["vulnerabilities"]:
                    print(f"- Type: {vuln['type']}")
                    print(f"  Details: {vuln['details']}")
            else:
                print("No CORS vulnerabilities detected.")
            print("\nDetails:")
            for test, headers in result["details"].items():
                print(f"  {test.replace('_', ' ').title()}:")
                for key, value in headers.items():
                    print(f"    {key}: {value}")

    print("\nCheck completed.")

if __name__ == "__main__":
    main()
