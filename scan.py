import argparse
import socket
import re
import dns.resolver
from termcolor import colored
import os
import requests

try:
    import sublist3r
except ModuleNotFoundError:
    os.system('pip install sublist3r')
    import sublist3r

try:
    from win_unicode_console import enable
    enable()
    from colorama import init, Fore
    init()
except ImportError:
    def colored(text, color):
        return text

    Fore = {
        'GREEN': '',
        'YELLOW': '',
        'BLUE': '',
        'RED': '',
    }


def no_color():
    global Fore
    Fore = {
        'GREEN': '',
        'YELLOW': '',
        'BLUE': '',
        'RED': '',
    }


def banner():
    print(colored("""
+=========================================+
| Author : Black Davil                    |
| Github : https://github.com/Black Davil |
+=========================================+
    """, 'red'))


def test_xss(subdomain):
    payloads = ["'><script>alert(1)</script>", "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>", "<svg><script>alert(1)</script></svg>"]
    url = f"http://{subdomain}"

    for payload in payloads:
        try:
            r = requests.get(f"{url}/{payload}")
            if payload in r.text:
                return True
        except:
            pass

    return False


def main():
    parser = argparse.ArgumentParser(
        description="Subdomain scanner using sublist3r")
    parser.add_argument('domain', type=str, help='the domain to scan')
    parser.add_argument('--threads', type=int, default=40,
                        help='number of threads to use')
    parser.add_argument('--no-color', action='store_true',
                        help='disable output coloring')
    args = parser.parse_args()

    if args.no_color:
        no_color()

    banner()

    domain = args.domain
    print(colored(f'Memulai pemindaian untuk {domain}', 'blue'))

    subdomains = sublist3r.main(
        domain, args.threads, None, True, None, False, False, None)

    ip_addresses = []
    for subdomain in subdomains:
        try:
            ip_address = socket.gethostbyname(subdomain)
            answers = dns.resolver.query(subdomain, 'A')
            ip_address = answers[0].address
            ip_addresses.append(ip_address)
        except socket.gaierror:
            ip_addresses.append(False)

    print(colored('\n=== Alamat IP ===', 'yellow'))
    for subdomain, ip_address in zip(subdomains, ip_addresses):
        if not ip_address:
            print(f'{subdomain} (tidak ditemukan alamat IP)')
        else:
            print(f'{subdomain} ({ip_address})')

    print(colored('\n=== Memeriksa kerentanan XSS ===', 'yellow'))
    for subdomain in subdomains:
        try:
            if test_xss(subdomain):
                print(
                    colored(f"{subdomain} mungkin rentan terhadap XSS!", 'red'))
            else:
                print(
                    colored(f"{subdomain} aman dari kerentanan XSS", 'green'))
        except:
            print(
                colored(f"Gagal memeriksa kerentanan XSS pada subdomain {subdomain}", 'red'))


if __name__ == '__main__':
    main()