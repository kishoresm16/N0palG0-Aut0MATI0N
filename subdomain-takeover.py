import requests
import argparse
import sys
import json
import dns.resolver
from requests.exceptions import HTTPError, RequestException

# Cloud provider patterns for CNAME checks
CLOUD_PROVIDERS = {
    "aws_s3": {
        "pattern": r"\.s3\.amazonaws\.com$",
        "check_url": "http://{cname}",
        "vulnerable_codes": [404],
        "description": "Unclaimed AWS S3 bucket"
    },
    "azure_blob": {
        "pattern": r"\.blob\.core\.windows\.net$",
        "check_url": "http://{cname}",
        "vulnerable_codes": [404, 403],
        "description": "Unclaimed Azure Blob Storage"
    },
    "github_pages": {
        "pattern": r"\.github\.io$",
        "check_url": "http://{cname}",
        "vulnerable_codes": [404],
        "description": "Unclaimed GitHub Pages site"
    },
    "heroku": {
        "pattern": r"\.herokuapp\.com$",
        "check_url": "http://{cname}",
        "vulnerable_codes": [404],
        "description": "Unclaimed Heroku app"
    }
}

def parse_args():
    parser = argparse.ArgumentParser(description="Subdomain Takeover Scanner")
    parser.add_argument("-d", "--domain", help="Single domain to check (e.g., example.com)")
    parser.add_argument("-D", "--subdomain-list", help="File containing list of subdomains (one per line)")
    parser.add_argument("-w", "--wordlist", help="Wordlist for subdomain brute-forcing (e.g., subdomains.txt)")
    parser.add_argument("--output", choices=["text", "json"], default="text", help="Output format (text or json)")
    return parser.parse_args()

def resolve_dns(subdomain, record_type='A'):
    """Resolve DNS records for a subdomain."""
    try:
        answers = dns.resolver.resolve(subdomain, record_type)
        return [str(rdata) for rdata in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
        return []
    except Exception as e:
        return [f"error: {str(e)}"]

def enumerate_subdomains(domain, wordlist=None):
    """Enumerate subdomains via DNS or brute-forcing."""
    subdomains = []
    
    # Check domain itself
    subdomains.append(domain)
    
    # Brute-force with wordlist
    if wordlist:
        try:
            with open(wordlist, "r") as f:
                words = [line.strip() for line in f if line.strip()]
            for word in words:
                subdomain = f"{word}.{domain}"
                if resolve_dns(subdomain, 'A') or resolve_dns(subdomain, 'CNAME'):
                    subdomains.append(subdomain)
        except FileNotFoundError:
            print(f"Error: Wordlist {wordlist} not found")
            sys.exit(1)
        except IOError as e:
            print(f"Error reading wordlist {wordlist}: {e}")
            sys.exit(1)
    
    return sorted(list(set(subdomains)))

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

def check_takeover(subdomain):
    """Check if a subdomain is vulnerable to takeover."""
    findings = []
    
    # Resolve CNAME records
    cnames = resolve_dns(subdomain, 'CNAME')
    if not cnames:
        return findings
    
    for cname in cnames:
        if cname.startswith("error:"):
            findings.append({
                "subdomain": subdomain,
                "cname": cname,
                "provider": "unknown",
                "status": "error",
                "details": cname
            })
            continue
        
        # Check against cloud providers
        for provider, config in CLOUD_PROVIDERS.items():
            if re.search(config["pattern"], cname):
                try:
                    url = config["check_url"].format(cname=cname)
                    response = requests.get(url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
                    status_code = response.status_code
                    if status_code in config["vulnerable_codes"]:
                        findings.append({
                            "subdomain": subdomain,
                            "cname": cname,
                            "provider": provider,
                            "status": "vulnerable",
                            "details": config["description"]
                        })
                    else:
                        findings.append({
                            "subdomain": subdomain,
                            "cname": cname,
                            "provider": provider,
                            "status": "not_vulnerable",
                            "details": f"Resource exists (HTTP {status_code})"
                        })
                except HTTPError:
                    # Suppress non-critical HTTP errors
                    pass
                except RequestException as e:
                    findings.append({
                        "subdomain": subdomain,
                        "cname": cname,
                        "provider": provider,
                        "status": "error",
                        "details": str(e)
                    })
    
    return findings

def main():
    args = parse_args()
    
    if not args.domain and not args.subdomain_list:
        print("Error: At least one of -d or -D is required")
        sys.exit(1)

    subdomains = []
    if args.domain:
        subdomains.extend(enumerate_subdomains(args.domain, args.wordlist))
    if args.subdomain_list:
        subdomains.extend(read_subdomains_from_file(args.subdomain_list))
    
    subdomains = sorted(list(set(subdomains)))
    if not subdomains:
        print("No subdomains found to scan")
        sys.exit(1)

    results = []
    for subdomain in subdomains:
        print(f"Checking {subdomain} for takeover..." if args.output == "text" else "", end="")
        findings = check_takeover(subdomain)
        results.append({
            "subdomain": subdomain,
            "findings": findings
        })
    
    # Output results
    if args.output == "json":
        print(json.dumps({"results": results}, indent=2))
    else:
        print("\n=== Subdomain Takeover Scan ===")
        vulnerable_found = False
        for result in results:
            if result["findings"]:
                for finding in result["findings"]:
                    if finding["status"] == "vulnerable":
                        vulnerable_found = True
                        print(f"\nVulnerable Subdomain: \033[91m{result['subdomain']}\033[0m")
                        print(f"  CNAME: {finding['cname']}")
                        print(f"  Provider: {finding['provider']}")
                        print(f"  Details: {finding['details']}")
                    elif finding["status"] == "error":
                        print(f"\nError for {result['subdomain']}:")
                        print(f"  Details: {finding['details']}")
        if not vulnerable_found:
            print("\nNo vulnerable subdomains found.")
    
    print("\nScan completed.")

if __name__ == "__main__":
    main()
