import sys
import requests
import json
import socket
import dns.resolver
import ssl
import OpenSSL
import cowsay
import colorama
from colorama import Fore, Style
import argparse
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor
import subprocess
import whois as WHOIS 

colorama.init(autoreset=True)

# Common subdomains to check
COMMON_SUBDOMAINS = ['www', 'mail', 'ftp', 'blog', 'test', 'dev', 'shop', 'api', 'staging']

# Common ports to scan
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Proxy"
}

def get_ip_address(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None

def get_location(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        return response.json()
    except requests.RequestException:
        return None

def get_ns_records(domain):
    try:
        result = dns.resolver.resolve(domain, 'NS')
        return [str(ns.to_text()) for ns in result]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return None

def get_mx_records(domain):
    try:
        result = dns.resolver.resolve(domain, 'MX')
        return [str(mx.to_text()) for mx in result]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return None

def get_ssl_certificate(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.connect((domain, 443))
            cert = s.getpeercert(True)
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)
            return {
                'issuer': {name.decode(): value.decode() for name, value in x509.get_issuer().get_components()},
                'subject': {name.decode(): value.decode() for name, value in x509.get_subject().get_components()},
                'notBefore': x509.get_notBefore().decode(),
                'notAfter': x509.get_notAfter().decode()
            }
    except Exception as e:
        return str(e)

def get_http_headers(domain):
    try:
        response = requests.head(f"http://{domain}")
        return response.headers
    except requests.RequestException:
        return None

def find_subdomains(domain):
    found_subdomains = []
    for subdomain in COMMON_SUBDOMAINS:
        subdomain_url = f"{subdomain}.{domain}"
        try:
            ip = socket.gethostbyname(subdomain_url)
            found_subdomains.append(subdomain_url)
        except socket.gaierror:
            pass
    return found_subdomains

def scan_ports(ip):
    open_ports = []
    for port, service in COMMON_PORTS.items():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append((port, service))
    return open_ports

def reverse_dns_lookup(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None

def whois_lookup(domain):
    try:
        domain_info = WHOIS.whois(domain)
        return domain_info
    except Exception as e:
        return str(e)

def technology_stack_detection(domain):
    try:
        result = subprocess.run(['whatweb', domain], capture_output=True, text=True)
        return result.stdout.strip()
    except Exception as e:
        return str(e)

def print_with_color(text, color):
    print(color + text + Style.RESET_ALL)

def main():
    parser = argparse.ArgumentParser(description="A tool for gathering information about a website.")
    parser.add_argument('domain', type=str, help='The domain name to analyze')
    args = parser.parse_args()

    # Print daemon with red color
    daemon_art = cowsay.get_output_string('daemon', "Welcome to InfoTool")
    print_with_color(daemon_art, Fore.RED)

    domain = args.domain
    ip_address = get_ip_address(domain)

    if not ip_address:
        print_with_color(f"Could not resolve IP address for {domain}", Fore.RED)
        sys.exit(1)

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(get_location, ip_address): 'location_info',
            executor.submit(get_ns_records, domain): 'ns_records',
            executor.submit(get_mx_records, domain): 'mx_records',
            executor.submit(get_ssl_certificate, domain): 'ssl_certificate',
            executor.submit(get_http_headers, domain): 'http_headers',
            executor.submit(find_subdomains, domain): 'subdomains',
            executor.submit(scan_ports, ip_address): 'open_ports',
            executor.submit(reverse_dns_lookup, ip_address): 'reverse_dns',
            executor.submit(whois_lookup, domain): 'whois_info',
            executor.submit(technology_stack_detection, domain): 'tech_stack'
        }
        results = {}
        for future in tqdm(futures, desc="Gathering information"):
            result = future.result()
            results[futures[future]] = result

    location_info = results.get('location_info')
    ns_records = results.get('ns_records')
    mx_records = results.get('mx_records')
    ssl_certificate = results.get('ssl_certificate')
    http_headers = results.get('http_headers')
    subdomains = results.get('subdomains')
    open_ports = results.get('open_ports')
    reverse_dns = results.get('reverse_dns')
    whois_info = results.get('whois_info')
    tech_stack = results.get('tech_stack')

    print_with_color(f"Website: {domain}", Fore.CYAN)
    print_with_color(f"IP Address: {ip_address}", Fore.CYAN)

    if reverse_dns:
        print_with_color(f"Reverse DNS: {reverse_dns}", Fore.GREEN)
    else:
        print_with_color("No Reverse DNS found", Fore.RED)

    print_with_color("Location Information:", Fore.GREEN)
    if location_info:
        print(json.dumps(location_info, indent=4))
    else:
        print_with_color("Could not retrieve location information", Fore.RED)

    print_with_color("\nNS Records:", Fore.GREEN)
    if ns_records:
        for ns in ns_records:
            print(f"- {ns}")
    else:
        print_with_color("Could not retrieve NS records", Fore.RED)

    print_with_color("\nMX Records:", Fore.GREEN)
    if mx_records:
        for mx in mx_records:
            print(f"- {mx}")
    else:
        print_with_color("Could not retrieve MX records", Fore.RED)

    print_with_color("\nSSL Certificate Information:", Fore.GREEN)
    if ssl_certificate and isinstance(ssl_certificate, dict):
        print(json.dumps(ssl_certificate, indent=4))
    else:
        print_with_color(f"Could not retrieve SSL certificate information: {ssl_certificate}", Fore.RED)

    print_with_color("\nHTTP Headers:", Fore.GREEN)
    if http_headers:
        for key, value in http_headers.items():
            print(f"{key}: {value}")
    else:
        print_with_color("Could not retrieve HTTP headers", Fore.RED)

    print_with_color("\nSubdomains:", Fore.GREEN)
    if subdomains:
        for subdomain in subdomains:
            print(f"- {subdomain}")
    else:
        print_with_color("No subdomains found", Fore.RED)

    print_with_color("\nOpen Ports:", Fore.GREEN)
    if open_ports:
        for port, service in open_ports:
            print(f"- Port {port} ({service}) is open")
    else:
        print_with_color("No common ports are open", Fore.RED)

    print_with_color("\nWHOIS Information:", Fore.GREEN)
    if isinstance(whois_info, dict):
        for key, value in whois_info.items():
            print(f"{key}: {value}")
    else:
        print_with_color(whois_info, Fore.RED)

    print_with_color("\nTechnology Stack:", Fore.GREEN)
    if tech_stack:
        print(tech_stack)
    else:
        print_with_color("Could not retrieve technology stack information", Fore.RED)

if __name__ == "__main__":
    main()
