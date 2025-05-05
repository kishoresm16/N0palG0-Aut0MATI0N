import requests
import pandas as pd
import argparse

# Function to read URLs from a file
def read_urls(file_path):
    with open(file_path, 'r') as file:
        urls = file.readlines()
    return [url.strip() for url in urls]

# List of security headers to check for
security_headers = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Feature-Policy"
]

# Function to check for missing security headers
def check_security_headers(urls):
    missing_headers = []
    
    for url in urls:
        # Ensure URL starts with http:// or https://
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        try:
            response = requests.get(url, timeout=5)
            headers = response.headers
            missing = [header for header in security_headers if header not in headers]
            
            if missing:
                missing_headers.append((url, ", ".join(missing)))
        
        except requests.exceptions.RequestException as e:
            print(f"Error fetching {url}: {e}")
    
    return missing_headers

def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Check for missing security headers in websites.")
    parser.add_argument('-d', '--domain', type=str, help="Single domain to check (e.g., example.com)")
    parser.add_argument('-D', '--domains-file', type=str, help="File containing list of domains")
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.domain and not args.domains_file:
        parser.error("You must provide either -d or -D option.")
    if args.domain and args.domains_file:
        parser.error("You can only use one of -d or -D at a time.")
    
    # Prepare URLs list
    if args.domain:
        urls = [args.domain]
    else:
        urls = read_urls(args.domains_file)
    
    # Get missing headers for the provided URLs
    missing_headers = check_security_headers(urls)
    
    # Convert the result into a pandas DataFrame for a tabular format
    df = pd.DataFrame(missing_headers, columns=["URL", "Missing Security Headers"])
    
    # Save the result to a text file
    output_file = 'missing_security_headers.txt'
    df.to_csv(output_file, index=False, sep='\t', header=True)
    
    print(f"Output saved to {output_file}")

if __name__ == "__main__":
    main()