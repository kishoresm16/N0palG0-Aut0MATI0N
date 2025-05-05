import requests
import argparse
import sys
import json
import re
import os
from bs4 import BeautifulSoup
import PyPDF2
from requests.exceptions import HTTPError, RequestException, ConnectionError
from urllib.parse import urljoin
from urllib3.exceptions import NameResolutionError as urllib3NameResolutionError

# Sensitive data patterns (expanded with new patterns)
SENSITIVE_PATTERNS = {
    "api_key": {
        "pattern": r"(?i)(api_key|api[-_]?token|access[-_]?token|secret[-_]?key)=[A-Za-z0-9]{16,64}",
        "description": "API Key or Access Token"
    },
    "aws_key": {
        "pattern": r"AKIA[0-9A-Z]{16}",
        "description": "AWS Access Key ID"
    },
    "aws_secret_key": {
        "pattern": r"(?i)[A-Za-z0-9/+=]{40}",
        "description": "AWS Secret Access Key"
    },
    "password": {
        "pattern": r"(?i)(password|pass|pwd)=[A-Za-z0-9!@#$%^&*]{8,}",
        "description": "Password"
    },
    "credit_card": {
        "pattern": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
        "description": "Credit Card Number"
    },
    "ssn": {
        "pattern": r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b",
        "description": "Social Security Number"
    },
    "email": {
        "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "description": "Email Address"
    },
    "phone": {
        "pattern": r"\b(\+\d{1,3}[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}\b",
        "description": "Phone Number"
    },
    "db_connection": {
        "pattern": r"(?i)(mysql|postgresql|mongodb)://[a-zA-Z0-9_-]+:[a-zA-Z0-9!@#$%^&*]+@[a-zA-Z0-9.-]+(?::\d+)?/[a-zA-Z0-9_-]+",
        "description": "Database Connection String"
    },
    "jwt_token": {
        "pattern": r"eyJ[a-zA-Z0-9_/+-]+\.eyJ[a-zA-Z0-9_/+-]+\.[a-zA-Z0-9_/+-]+",
        "description": "JSON Web Token (JWT)"
    },
    "private_key": {
        "pattern": r"-----BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE KEY-----[\s\S]+?-----END (RSA|OPENSSH|EC|DSA) PRIVATE KEY-----",
        "description": "SSH/RSA Private Key"
    },
    "github_token": {
        "pattern": r"ghp_[A-Za-z0-9]{36}",
        "description": "GitHub Personal Access Token"
    },
    "slack_token": {
        "pattern": r"xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{32}",
        "description": "Slack API Token"
    },
    "twilio_key": {
        "pattern": r"SK[0-9a-fA-F]{32}",
        "description": "Twilio API Key"
    },
    "stripe_key": {
        "pattern": r"(?i)(sk|rk)_live_[0-9a-zA-Z]{24,34}",
        "description": "Stripe API Key"
    },
    "azure_sas": {
        "pattern": r"sig=[A-Za-z0-9%_]{44}",
        "description": "Azure Shared Access Signature"
    },
    "gcp_service_key": {
        "pattern": r"\"private_key_id\":\s*\"[0-9a-f]{40}\"",
        "description": "Google Cloud Service Account Key ID"
    },
    "crypto_key": {
        "pattern": r"\b[0-9a-fA-F]{64}\b",
        "description": "Cryptographic Key (e.g., AES)"
    },
    "medical_record": {
        "pattern": r"\b[A-Z]?[0-9]{6,8}\b",
        "description": "Medical Record Number"
    },
    "bank_account": {
        "pattern": r"\b[0-9]{8,12}\b",
        "description": "Bank Account Number"
    },
    "oauth_secret": {
        "pattern": r"(?i)client_secret=[A-Za-z0-9_-]{32,64}",
        "description": "OAuth Client Secret"
    },
    "env_variable": {
        "pattern": r"(?i)(DB_PASSWORD|SECRET_KEY|API_KEY)=[A-Za-z0-9!@#$%^&*_-]{8,}",
        "description": "Environment Variable (e.g., .env)"
    },
    "ip_credentials": {
        "pattern": r"(?i)(ftp|http|https)://[a-zA-Z0-9_-]+:[a-zA-Z0-9!@#$%^&*]+@(?:\d{1,3}\.){3}\d{1,3}",
        "description": "IP Address with Credentials"
    },
    "crypto_wallet": {
        "pattern": r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|\b[0-9a-fA-F]{64}\b",
        "description": "Cryptocurrency Wallet Private Key"
    }
}

# Supported file extensions
FILE_EXTENSIONS = [".txt", ".js", ".json", ".pdf"]

def parse_args():
    parser = argparse.ArgumentParser(description="Sensitive Data Exposure Scanner")
    parser.add_argument("-u", "--url", help="Single URL to scan (e.g., https://example.com)")
    parser.add_argument("-U", "--url-list", help="File containing list of URLs (one per line)")
    parser.add_argument("-f", "--files", help="Directory containing files to scan (e.g., /path/to/files)")
    parser.add_argument("-b", "--buckets", help="JSON file with bucket URLs from cloud storage scanner")
    parser.add_argument("--max-depth", type=int, default=2, help="Maximum crawling depth (default: 2)")
    parser.add_argument("--output", choices=["text", "json"], default="text", help="Output format (text or json)")
    parser.add_argument("--verbose", action="store_true", help="Show all findings, including errors")
    return parser.parse_args()

def read_urls_from_file(file_path):
    """Read URLs from a file."""
    try:
        with open(file_path, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: File {file_path} not found")
        sys.exit(1)
    except IOError as e:
        print(f"Error reading file {file_path}: {e}")
        sys.exit(1)

def read_buckets_from_json(file_path):
    """Read bucket URLs from JSON file (from Misconfigured Cloud Storage Scanner)."""
    try:
        with open(file_path, "r") as f:
            data = json.load(f)
        urls = []
        for result in data.get("results", []):
            for finding in result.get("findings", []):
                if finding["status"] in ["public_read", "public_write"]:
                    urls.append(finding["url"])
                    for content in finding.get("contents", []):
                        if any(content.lower().endswith(ext) for ext in FILE_EXTENSIONS):
                            urls.append(f"{finding['url']}/{content}")
        return urls
    except FileNotFoundError:
        print(f"Error: File {file_path} not found")
        sys.exit(1)
    except (IOError, json.JSONDecodeError) as e:
        print(f"Error reading JSON file {file_path}: {e}")
        sys.exit(1)

def crawl_url(url, max_depth, visited=None):
    """Crawl a URL for links and files up to max_depth."""
    if visited is None:
        visited = set()
    if max_depth < 0 or url in visited:
        return []
    
    urls = [url]
    visited.add(url)
    
    try:
        response = requests.get(url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
        
        for link in soup.find_all("a", href=True):
            href = link["href"]
            absolute_url = urljoin(url, href)
            if any(absolute_url.lower().endswith(ext) for ext in FILE_EXTENSIONS):
                urls.append(absolute_url)
            elif absolute_url.startswith(url) and absolute_url not in visited:
                urls.extend(crawl_url(absolute_url, max_depth - 1, visited))
    except (HTTPError, RequestException):
        pass
    
    return list(set(urls))

def scan_content(content, source, is_pdf=False):
    """Scan content for sensitive data using regex patterns."""
    findings = []
    for data_type, config in SENSITIVE_PATTERNS.items():
        matches = re.finditer(config["pattern"], content, re.MULTILINE)
        for match in matches:
            findings.append({
                "source": source,
                "data_type": data_type,
                "value": match.group(0),
                "description": config["description"],
                "status": "exposed"
            })
    return findings

def scan_web_content(url, max_depth):
    """Scan web page and linked files for sensitive data."""
    findings = []
    urls = crawl_url(url, max_depth)
    
    for u in urls:
        try:
            response = requests.get(u, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
            response.raise_for_status()
            
            if u.lower().endswith(".pdf"):
                # Handle PDF
                with open("temp.pdf", "wb") as f:
                    f.write(response.content)
                try:
                    with open("temp.pdf", "rb") as f:
                        reader = PyPDF2.PdfReader(f)
                        content = ""
                        for page in reader.pages:
                            content += page.extract_text() or ""
                    findings.extend(scan_content(content, u, is_pdf=True))
                except Exception as e:
                    findings.append({
                        "source": u,
                        "data_type": "error",
                        "value": "",
                        "description": f"PDF processing error: {str(e)}",
                        "status": "error"
                    })
                finally:
                    if os.path.exists("temp.pdf"):
                        os.remove("temp.pdf")
            else:
                # Handle text-based content (HTML, .txt, .js, .json)
                content = response.text
                findings.extend(scan_content(content, u))
        except ConnectionError as e:
            if isinstance(e.__cause__, urllib3NameResolutionError):
                findings.append({
                    "source": u,
                    "data_type": "error",
                    "value": "",
                    "description": f"DNS resolution failed",
                    "status": "error"
                })
            else:
                findings.append({
                    "source": u,
                    "data_type": "error",
                    "value": "",
                    "description": f"Connection error: {str(e)}",
                    "status": "error"
                })
        except (HTTPError, RequestException) as e:
            findings.append({
                "source": u,
                "data_type": "error",
                "value": "",
                "description": f"Request error: {str(e)}",
                "status": "error"
            })
    
    return findings

def scan_local_files(directory):
    """Scan local files in a directory for sensitive data."""
    findings = []
    
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            if any(file.lower().endswith(ext) for ext in FILE_EXTENSIONS):
                try:
                    if file.lower().endswith(".pdf"):
                        with open(file_path, "rb") as f:
                            reader = PyPDF2.PdfReader(f)
                            content = ""
                            for page in reader.pages:
                                content += page.extract_text() or ""
                        findings.extend(scan_content(content, file_path, is_pdf=True))
                    else:
                        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                        findings.extend(scan_content(content, file_path))
                except Exception as e:
                    findings.append({
                        "source": file_path,
                        "data_type": "error",
                        "value": "",
                        "description": f"File processing error: {str(e)}",
                        "status": "error"
                    })
    
    return findings

def main():
    args = parse_args()
    
    if not any([args.url, args.url_list, args.files, args.buckets]):
        print("Error: At least one of -u, -U, -f, or -b is required")
        sys.exit(1)

    urls = []
    if args.url:
        urls.append(args.url)
    if args.url_list:
        urls.extend(read_urls_from_file(args.url_list))
    if args.buckets:
        urls.extend(read_buckets_from_json(args.buckets))
    
    results = []
    
    # Scan web URLs
    for url in urls:
        print(f"Scanning {url}..." if args.output == "text" else "", end="")
        findings = scan_web_content(url, args.max_depth)
        results.append({"source": url, "findings": findings})
    
    # Scan local files
    if args.files:
        print(f"Scanning files in {args.files}..." if args.output == "text" else "", end="")
        findings = scan_local_files(args.files)
        results.append({"source": args.files, "findings": findings})
    
    # Output results
    if args.output == "json":
        print(json.dumps({"results": results}, indent=2))
    else:
        print("\n=== Sensitive Data Exposure Scan ===")
        exposed_found = False
        for result in results:
            for finding in result["findings"]:
                if finding["status"] == "exposed":
                    exposed_found = True
                    print(f"\nExposed Data in: {result['source']}")
                    print(f"  Type: {finding['data_type']}")
                    print(f"  Value: \033[91m{finding['value']}\033[0m")
                    print(f"  Description: {finding['description']}")
                elif finding["status"] == "error" and args.verbose:
                    print(f"\nError in: {result['source']}")
                    print(f"  Details: {finding['description']}")
        if not exposed_found:
            print("\nNo sensitive data found.")
    
    print("\nScan completed.")

if __name__ == "__main__":
    main()
