import socket
import ssl
import dns.resolver
import requests
import json
import OpenSSL
import re
from ipwhois import IPWhois
from rich.console import Console
from rich.table import Table
from rich import box
from rich.panel import Panel
from rich.markdown import Markdown
import pyfiglet
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import time
import collections

console = Console()

def print_banner(text):
    banner = pyfiglet.figlet_format(text, font="slant")
    console.print(banner, style="bold cyan")

def get_ip_and_hosting_info(ip):
    try:
        obj = IPWhois(ip)
        results = obj.lookup_rdap()
        return results
    except Exception as e:
        return {"error": str(e)}

def get_website_info(url):
    try:
        if not re.match(r'^https?://', url):
            url = 'http://' + url
        start_time = time.time()
        response = requests.get(url)
        load_time = time.time() - start_time
        server = response.headers.get('Server')
        headers = response.headers
        security_headers = {
            'Content-Security-Policy': response.headers.get('Content-Security-Policy'),
            'Strict-Transport-Security': response.headers.get('Strict-Transport-Security'),
            'X-Frame-Options': response.headers.get('X-Frame-Options'),
            'X-Content-Type-Options': response.headers.get('X-Content-Type-Options'),
            'X-XSS-Protection': response.headers.get('X-XSS-Protection')
        }

        soup = BeautifulSoup(response.content, 'html.parser')
        links = [a['href'] for a in soup.find_all('a', href=True) if not urlparse(a['href']).netloc == urlparse(url).netloc]
        word_count = collections.Counter(soup.get_text().split())

        return {
            'Server': server,
            'Headers': headers,
            'Security Headers': security_headers,
            'Load Time': load_time,
            'External Links': links,
            'Word Count': word_count.most_common(10)
        }
    except Exception as e:
        return {"error": str(e)}

def get_ssl_info(domain):
    try:
        cert = ssl.get_server_certificate((domain, 443))
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        return {
            'Issuer': dict(x509.get_issuer().get_components()),
            'Subject': dict(x509.get_subject().get_components()),
            'Serial Number': x509.get_serial_number(),
            'Version': x509.get_version(),
            'Not Before': x509.get_notBefore().decode('utf-8'),
            'Not After': x509.get_notAfter().decode('utf-8'),
            'Signature Algorithm': x509.get_signature_algorithm().decode('utf-8'),
            'SANs': [x.decode('utf-8') for x in x509.get_extension(2).get_data().split(b'\x82')[1:]]
        }
    except Exception as e:
        return {"error": str(e)}

def get_dns_info(domain):
    try:
        result = dns.resolver.resolve(domain, 'A')
        return [ip.to_text() for ip in result]
    except Exception as e:
        return {"error": str(e)}

def get_technology_stack(url):
    try:
        if not re.match(r'^https?://', url):
            url = 'http://' + url
        response = requests.get(url)
        stack = {
            'Server': response.headers.get('Server'),
            'X-Powered-By': response.headers.get('X-Powered-By'),
        }
        return stack
    except Exception as e:
        return {"error": str(e)}

def get_subdomains(domain):
    try:
        subdomains = []
        result = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
        for rdata in result:
            if 'v=DMARC1' in rdata.to_text():
                subdomains.append(f'_dmarc.{domain}')
        return subdomains
    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    url = input("Enter the website URL (without 'http://' (or) 'https://'): ")

    domain = url.strip().replace('www.', '').split('/')[0]

    print_banner("WebProfyler")

    console.print(Panel("[bold cyan]Website Info[/bold cyan]", box=box.DOUBLE))
    website_info = get_website_info(domain)
    if "error" in website_info:
        console.print(f"[bold red]Error fetching website information: {website_info['error']}[/bold red]")
    else:
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Field", style="dim", width=20)
        table.add_column("Value", style="bold")
        table.add_row("Server", website_info.get('Server', 'N/A'))
        table.add_row("Load Time", str(website_info.get('Load Time', 'N/A')))
        for key, value in website_info['Headers'].items():
            table.add_row(key, str(value))
        console.print(table)

        console.print(Panel("[bold cyan]Security Headers[/bold cyan]", box=box.DOUBLE))
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Header", style="dim", width=30)
        table.add_column("Value", style="bold")
        for key, value in website_info['Security Headers'].items():
            table.add_row(key, str(value))
        console.print(table)

        console.print(Panel("[bold cyan]Content Analysis[/bold cyan]", box=box.DOUBLE))
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Field", style="dim", width=30)
        table.add_column("Value", style="bold")
        for word, count in website_info['Word Count']:
            table.add_row(word, str(count))
        console.print(table)

        console.print(Panel("[bold cyan]External Links[/bold cyan]", box=box.DOUBLE))
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("External Link", style="bold")
        for link in website_info['External Links']:
            table.add_row(link)
        console.print(table)

    console.print(Panel("[bold cyan]IP and Hosting Info[/bold cyan]", box=box.DOUBLE))
    try:
        ip_address = socket.gethostbyname(domain)
        ip_info = get_ip_and_hosting_info(ip_address)
        if "error" in ip_info:
            console.print(f"[bold red]Error fetching IP information: {ip_info['error']}[/bold red]")
        else:
            table = Table(show_header=True, header_style="bold cyan")
            table.add_column("Field", style="dim", width=20)
            table.add_column("Value", style="bold")
            for key, value in ip_info.items():
                table.add_row(key, str(value))
            console.print(table)
    except Exception as e:
        console.print(f"[bold red]Error fetching IP information: {e}[/bold red]")

    console.print(Panel("[bold cyan]SSL Info[/bold cyan]", box=box.DOUBLE))
    ssl_info = get_ssl_info(domain)
    if "error" in ssl_info:
        console.print(f"[bold red]Error fetching SSL information: {ssl_info['error']}[/bold red]")
    else:
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Field", style="dim", width=20)
        table.add_column("Value", style="bold")
        for key, value in ssl_info.items():
            table.add_row(key, str(value))
        console.print(table)

    console.print(Panel("[bold cyan]DNS Info[/bold cyan]", box=box.DOUBLE))
    dns_info = get_dns_info(domain)
    if "error" in dns_info:
        console.print(f"[bold red]Error fetching DNS information: {dns_info['error']}[/bold red]")
    else:
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("IP Address", style="bold")
        for ip in dns_info:
            table.add_row(ip)
        console.print(table)

    console.print(Panel("[bold cyan]Technology Stack[/bold cyan]", box=box.DOUBLE))
    tech_stack = get_technology_stack(domain)
    if "error" in tech_stack:
        console.print(f"[bold red]Error fetching technology stack information: {tech_stack['error']}[/bold red]")
    else:
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Field", style="dim", width=20)
        table.add_column("Value", style="bold")
        for key, value in tech_stack.items():
            table.add_row(key, str(value))
        console.print(table)

    console.print(Panel("[bold cyan]Subdomains[/bold cyan]", box=box.DOUBLE))
    subdomains = get_subdomains(domain)
    if "error" in subdomains:
        console.print(f"[bold red]Error fetching subdomains: {subdomains['error']}[/bold red]")
    else:
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Subdomain", style="bold")
        for subdomain in subdomains:
            table.add_row(subdomain)
        console.print(table)
