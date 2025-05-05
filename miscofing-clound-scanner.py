import requests
import argparse
import sys
import json
import re
import xml.etree.ElementTree as ET
from requests.exceptions import HTTPError, RequestException, ConnectionError
from urllib3.exceptions import NameResolutionError as urllib3NameResolutionError

# Cloud provider configurations
CLOUD_PROVIDERS = {
    "aws_s3": {
        "url_template": "http://{bucket}.s3.amazonaws.com",
        "public_read_codes": [200],
        "public_write_method": "PUT",
        "exists_codes": [403],
        "non_existent_codes": [404],
        "description": "AWS S3 Bucket"
    },
    "azure_blob": {
        "url_template": "http://{bucket}.blob.core.windows.net",
        "public_read_codes": [200, 206],
        "public_write_method": None,  # Azure requires auth for write
        "exists_codes": [403],
        "non_existent_codes": [404],
        "description": "Azure Blob Storage"
    },
    "google_cloud": {
        "url_template": "http://{bucket}.storage.googleapis.com",
        "public_read_codes": [200],
        "public_write_method": None,  # GCP requires auth for write
        "exists_codes": [403],
        "non_existent_codes": [404],
        "description": "Google Cloud Storage"
    }
}

def parse_args():
    parser = argparse.ArgumentParser(description="Misconfigured Cloud Storage Scanner")
    parser.add_argument("-d", "--domain", help="Single domain to check (e.g., example.com)")
    parser.add_argument("-D", "--subdomain-list", help="File containing list of subdomains (one per line)")
    parser.add_argument("-k", "--keyword", help="Keyword for bucket enumeration (e.g., companyname)")
    parser.add_argument("-w", "--wordlist", help="Wordlist for bucket name generation (e.g., words.txt)")
    parser.add_argument("--output", choices=["text", "json"], default="text", help="Output format (text or json)")
    parser.add_argument("--verbose", action="store_true", help="Show all findings, including non-existent buckets")
    return parser.parse_args()

def generate_bucket_names(domain=None, subdomains=None, keyword=None, wordlist=None):
    """Generate potential bucket names."""
    buckets = set()
    
    # From domain
    if domain:
        domain_clean = domain.lower().replace("www.", "").split(":")[0]
        buckets.add(domain_clean)
        buckets.add(domain_clean.replace(".", "-"))
        buckets.add(domain_clean.replace(".", ""))
    
    # From subdomains
    if subdomains:
        for subdomain in subdomains:
            subdomain_clean = subdomain.lower().replace("www.", "").split(":")[0]
            buckets.add(subdomain_clean)
            buckets.add(subdomain_clean.replace(".", "-"))
            buckets.add(subdomain_clean.replace(".", ""))
    
    # From keyword
    if keyword:
        keyword_clean = keyword.lower().strip()
        buckets.add(keyword_clean)
        buckets.add(keyword_clean.replace(" ", "-"))
        buckets.add(keyword_clean.replace(" ", ""))
    
    # From wordlist
    if wordlist:
        try:
            with open(wordlist, "r") as f:
                words = [line.strip().lower() for line in f if line.strip()]
            for word in words:
                buckets.add(word)
                if domain:
                    buckets.add(f"{word}-{domain.replace('.', '-')}")
                if keyword:
                    buckets.add(f"{word}-{keyword.replace(' ', '-')}")
        except FileNotFoundError:
            print(f"Error: Wordlist {wordlist} not found")
            sys.exit(1)
        except IOError as e:
            print(f"Error reading wordlist {wordlist}: {e}")
            sys.exit(1)
    
    return sorted(list(buckets))

def read_subdomains_from_file(file_path):
    """Read subdomains from a file."""
    try:
        with open(file_path, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: File {file_path} not found")
        sys.exit(1)
    except IOError as e:
        print(f"Error reading file {file_path}: {e}")
        sys.exit(1)

def check_bucket(bucket, provider):
    """Check if a bucket is publicly accessible or exists."""
    findings = []
    url = CLOUD_PROVIDERS[provider]["url_template"].format(bucket=bucket)
    
    # Check for public read access
    try:
        response = requests.get(url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
        status_code = response.status_code
        
        if status_code in CLOUD_PROVIDERS[provider]["public_read_codes"]:
            # Check for S3 XML listing
            contents = []
            if provider == "aws_s3":
                try:
                    root = ET.fromstring(response.text)
                    for content in root.findall(".//{http://s3.amazonaws.com/doc/2006-03-01/}Key"):
                        contents.append(content.text)
                except ET.ParseError:
                    contents = ["Non-XML content"]
            else:
                contents = ["Accessible content"]
            
            findings.append({
                "bucket": bucket,
                "url": url,
                "provider": provider,
                "status": "public_read",
                "details": f"Publicly readable ({CLOUD_PROVIDERS[provider]['description']})",
                "contents": contents[:5]  # Limit to 5 items
            })
        elif status_code in CLOUD_PROVIDERS[provider]["exists_codes"]:
            findings.append({
                "bucket": bucket,
                "url": url,
                "provider": provider,
                "status": "exists_private",
                "details": f"Bucket exists but is private (HTTP {status_code})",
                "contents": []
            })
        elif status_code in CLOUD_PROVIDERS[provider]["non_existent_codes"]:
            findings.append({
                "bucket": bucket,
                "url": url,
                "provider": provider,
                "status": "non_existent",
                "details": f"Bucket does not exist (HTTP {status_code})",
                "contents": []
            })
    except ConnectionError as e:
        if isinstance(e.__cause__, urllib3NameResolutionError):
            findings.append({
                "bucket": bucket,
                "url": url,
                "provider": provider,
                "status": "non_existent",
                "details": f"Bucket does not exist (DNS resolution failed)",
                "contents": []
            })
        else:
            findings.append({
                "bucket": bucket,
                "url": url,
                "provider": provider,
                "status": "error",
                "details": f"Error: {str(e)}",
                "contents": []
            })
    except HTTPError:
        # Suppress non-critical HTTP errors
        pass
    except RequestException as e:
        findings.append({
            "bucket": bucket,
            "url": url,
            "provider": provider,
            "status": "error",
            "details": f"Error: {str(e)}",
            "contents": []
        })
    
    # Check for public write access (S3 only)
    if provider == "aws_s3" and CLOUD_PROVIDERS[provider]["public_write_method"]:
        try:
            # Non-destructive PUT test (minimal data)
            response = requests.put(f"{url}/test.txt", data="test", timeout=5, headers={"User-Agent": "Mozilla/5.0"})
            if response.status_code in [200, 201]:
                findings.append({
                    "bucket": bucket,
                    "url": url,
                    "provider": provider,
                    "status": "public_write",
                    "details": f"Publicly writable ({CLOUD_PROVIDERS[provider]['description']})",
                    "contents": []
                })
        except ConnectionError as e:
            if isinstance(e.__cause__, urllib3NameResolutionError):
                findings.append({
                    "bucket": bucket,
                    "url": url,
                    "provider": provider,
                    "status": "non_existent",
                    "details": f"Bucket does not exist (DNS resolution failed)",
                    "contents": []
                })
            else:
                findings.append({
                    "bucket": bucket,
                    "url": url,
                    "provider": provider,
                    "status": "error",
                    "details": f"Write test error: {str(e)}",
                    "contents": []
                })
        except RequestException as e:
            findings.append({
                "bucket": bucket,
                "url": url,
                "provider": provider,
                "status": "error",
                "details": f"Write test error: {str(e)}",
                "contents": []
            })
    
    return findings

def main():
    args = parse_args()
    
    if not any([args.domain, args.subdomain_list, args.keyword]):
        print("Error: At least one of -d, -D, or -k is required")
        sys.exit(1)

    # Collect subdomains
    subdomains = []
    if args.subdomain_list:
        subdomains.extend(read_subdomains_from_file(args.subdomain_list))
    
    # Generate bucket names
    buckets = generate_bucket_names(
        domain=args.domain,
        subdomains=subdomains,
        keyword=args.keyword,
        wordlist=args.wordlist
    )
    
    if not buckets:
        print("No bucket names generated")
        sys.exit(1)

    results = []
    for bucket in buckets:
        bucket_results = {"bucket": bucket, "findings": []}
        for provider in CLOUD_PROVIDERS:
            print(f"Checking {bucket} for {provider}..." if args.output == "text" else "", end="")
            findings = check_bucket(bucket, provider)
            bucket_results["findings"].extend(findings)
        results.append(bucket_results)
    
    # Output results
    if args.output == "json":
        print(json.dumps({"results": results}, indent=2))
    else:
        print("\n=== Cloud Storage Misconfiguration Scan ===")
        public_found = False
        for result in results:
            for finding in result["findings"]:
                if finding["status"] in ["public_read", "public_write"]:
                    public_found = True
                    print(f"\nPublic Bucket: \033[91m{finding['url']}\033[0m")
                    print(f"  Provider: {finding['provider']}")
                    print(f"  Status: {finding['status']}")
                    print(f"  Details: {finding['details']}")
                    if finding["contents"]:
                        print(f"  Contents: {', '.join(finding['contents'])}")
                elif finding["status"] == "error" and args.verbose:
                    print(f"\nError for {result['bucket']} ({finding['provider']}):")
                    print(f"  Details: {finding['details']}")
                elif finding["status"] in ["exists_private", "non_existent"] and args.verbose:
                    print(f"\nStatus for {result['bucket']} ({finding['provider']}):")
                    print(f"  Details: {finding['details']}")
        if not public_found:
            print("\nNo publicly accessible buckets found.")
    
    print("\nScan completed.")

if __name__ == "__main__":
    main()
