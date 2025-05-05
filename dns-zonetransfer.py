import dns.resolver
import dns.query
import dns.zone
import dns.rdatatype
import argparse
import sys
import json
from dns.exception import DNSException
from socket import gaierror

def parse_args():
    parser = argparse.ArgumentParser(description="DNS Zone Transfer Vulnerability Checker")
    parser.add_argument("-d", "--domain", help="Single domain to check (e.g., example.com)")
    parser.add_argument("-D", "--domain-list", help="File containing list of domains (one per line)")
    parser.add_argument("--ns", help="Specific nameserver to test (e.g., ns1.example.com)")
    parser.add_argument("--output", choices=["text", "json"], default="text", help="Output format (text or json)")
    parser.add_argument("--verbose", action="store_true", help="Show all findings, including errors")
    return parser.parse_args()

def read_domains_from_file(file_path):
    """Read domains from a file."""
    try:
        with open(file_path, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: File {file_path} not found")
        sys.exit(1)
    except IOError as e:
        print(f"Error reading file {file_path}: {e}")
        sys.exit(1)

def get_nameservers(domain):
    """Resolve nameservers for a domain."""
    try:
        resolver = dns.resolver.Resolver()
        answers = resolver.resolve(domain, 'NS')
        return [str(rdata.target) for rdata in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, DNSException) as e:
        return []
    except Exception as e:
        return []

def attempt_zone_transfer(domain, nameserver):
    """Attempt DNS zone transfer (AXFR) on a nameserver."""
    findings = []
    try:
        # Resolve nameserver IP
        resolver = dns.resolver.Resolver()
        answers = resolver.resolve(nameserver, 'A')
        ns_ip = str(answers[0])

        # Attempt AXFR
        zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain))
        records = []
        for name, node in zone.nodes.items():
            for rdataset in node.rdatasets:
                for rdata in rdataset:
                    record = {
                        "name": str(name),
                        "type": dns.rdatatype.to_text(rdataset.rdtype),
                        "data": str(rdata)
                    }
                    records.append(record)
        
        findings.append({
            "domain": domain,
            "nameserver": nameserver,
            "status": "vulnerable",
            "details": f"Zone transfer succeeded on {nameserver}",
            "records": records
        })
    except (dns.query.TransferError, dns.zone.NoSOA, dns.zone.NoNS) as e:
        findings.append({
            "domain": domain,
            "nameserver": nameserver,
            "status": "not_vulnerable",
            "details": f"Zone transfer failed: {str(e)}",
            "records": []
        })
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, gaierror) as e:
        findings.append({
            "domain": domain,
            "nameserver": nameserver,
            "status": "error",
            "details": f"Error: {str(e)}",
            "records": []
        })
    except Exception as e:
        findings.append({
            "domain": domain,
            "nameserver": nameserver,
            "status": "error",
            "details": f"Unexpected error: {str(e)}",
            "records": []
        })
    
    return findings

def main():
    args = parse_args()
    
    if not any([args.domain, args.domain_list]):
        print("Error: At least one of -d or -D is required")
        sys.exit(1)

    domains = []
    if args.domain:
        domains.append(args.domain)
    if args.domain_list:
        domains.extend(read_domains_from_file(args.domain_list))
    
    results = []
    
    for domain in domains:
        print(f"Checking {domain}..." if args.output == "text" else "", end="")
        domain_results = {"domain": domain, "findings": []}
        
        # Get nameservers or use provided one
        nameservers = [args.ns] if args.ns else get_nameservers(domain)
        
        if not nameservers:
            domain_results["findings"].append({
                "domain": domain,
                "nameserver": None,
                "status": "error",
                "details": "No nameservers found",
                "records": []
            })
        else:
            for ns in nameservers:
                findings = attempt_zone_transfer(domain, ns)
                domain_results["findings"].extend(findings)
        
        results.append(domain_results)
    
    # Output results
    if args.output == "json":
        print(json.dumps({"results": results}, indent=2))
    else:
        print("\n=== DNS Zone Transfer Vulnerability Scan ===")
        vulnerable_found = False
        for result in results:
            for finding in result["findings"]:
                if finding["status"] == "vulnerable":
                    vulnerable_found = True
                    print(f"\nVulnerable Zone Transfer: \033[91m{result['domain']} on {finding['nameserver']}\033[0m")
                    print(f"  Details: {finding['details']}")
                    print(f"  Records (first 5):")
                    for record in finding["records"][:5]:
                        print(f"    {record['name']} {record['type']} {record['data']}")
                elif finding["status"] == "error" and args.verbose:
                    print(f"\nError for {result['domain']} ({finding['nameserver'] or 'no nameserver'}):")
                    print(f"  Details: {finding['details']}")
                elif finding["status"] == "not_vulnerable" and args.verbose:
                    print(f"\nStatus for {result['domain']} ({finding['nameserver']}):")
                    print(f"  Details: {finding['details']}")
        if not vulnerable_found:
            print("\nNo zone transfer vulnerabilities found.")
    
    print("\nScan completed.")

if __name__ == "__main__":
    main()
