import dns.resolver
import nmap
import whois
import re
import socket
import os
from colorama import Fore, init, Back, Style
init()

while True:

    def what_you_have():
        ip_or_domain = input("What you have IP or Domain?: ").lower()
        while ip_or_domain not in ("ip", "domain"):
            print("Enter valid input, try again!!!")
            ip_or_domain = input("What you have IP or Domain?: ").lower()
        if ip_or_domain == "ip":
            ip = input('Enter IP address: ')
            if validate_ip(ip):
                options = input("Choose one: \nreversedns \nNMAP scan\nWHOIS scan\nNSLOOKUP scan\n: ").lower()
                while options not in ("reversedns", "nmap scan", "whois scan", "nslookup scan"):
                    print("Choose valid option")
                    options = input("Choose one: \nreversedns \nNMAP scan\nWHOIS scan\nNSLOOKUP scan\n: ").lower()
                if options == "reversedns":
                    reverse_dns(ip=ip)
                if options == "nmap scan":
                    nmap_scanning(ip)
                if options == "whois scan":
                    whois_scanning(ip=ip)
                    print("WHOIS may not return data for raw IPs. Consider using a domain instead.")
                if options == "nslookup scan":
                    nslookup_scan(ip=ip)
            else:
                print("Enter valid IP, try again!!")
        if ip_or_domain == "domain":
            domain = input("Enter domain name in (google.com or openai.com) format: ").lower()
            if validate_domain(domain):
                options = input("Choose one: \nGet IP\nNMAP scan\nWHOIS scan\nNSLOOKUP scan\n: ").lower()
                while options not in ("get ip", "nmap scan", "whois scan", "nslookup scan"):
                    print("Enter valid option, try again!!")
                    options = input("Choose one: \nGet IP\nNMAP scan\nWHOIS scan\nNSLOOKUP scan\n: ").lower()
                if options == "get ip":
                    print(Fore.RED + get_ip(domain))
                elif options == "nmap scan":
                    ip = get_ip(domain)
                    nmap_scanning(ip)
                elif options == "whois scan":
                    whois_scanning(domain=domain)
                elif options == "nslookup scan":
                    nslookup_scan(domain=domain)
            else:
                print("Enter valid domain, try again!!")

    def validate_ip(ip):
        pattern = r"^(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})(\.(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})){3}$"
        return re.match(pattern, ip)

    def validate_domain(domain):
        pattern = r"^(?!www\.)([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"
        return re.match(pattern, domain)

    def get_ip(domain):
        ip = socket.gethostbyname(domain)
        return(ip)

    def nmap_scanning(ip):
        target = ip
        scanner = nmap.PortScanner()
        print(f"{Fore.YELLOW}Scanning {target} on most common ports...{Style.RESET_ALL}")

        try:
            scanner.scan(ip, arguments='-O')
            print(Fore.BLACK + scanner[ip]['osmatch'][0]['name'])

            scanner.scan(hosts=target, arguments='-Pn')  # -Pn skips host discovery
            for port in scanner[target]['tcp']:
                state = scanner[target]['tcp'][port]['state']
                name = scanner[target]['tcp'][port]['name']
                print(f"{Fore.GREEN}Port {port} ({name}) is {state}.{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}Nmap scan failed: {e}{Style.RESET_ALL}")



    def whois_scanning(ip=None, domain=None):
        if ip:
            print(f"{Fore.YELLOW}Running with IP: {ip}{Style.RESET_ALL}")
            try:
                info = whois.whois(ip)
                print(Fore.BLUE + str(info) + Style.RESET_ALL)
            except Exception as e:
                print(f"{Fore.RED}WHOIS failed on IP: {e}{Style.RESET_ALL}")

        elif domain:
            print(f"{Fore.YELLOW}Running with domain: {domain}{Style.RESET_ALL}")
            try:
                ip_from_domain = socket.gethostbyname(domain)
                print(f"{Fore.CYAN}Resolved IP: {ip_from_domain}{Style.RESET_ALL}")
                info = whois.whois(domain)
                print(Fore.BLUE + str(info) + Style.RESET_ALL)
            except Exception as e:
                print(f"{Fore.RED}WHOIS failed on domain: {e}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Error: You must provide either an IP or a Domain.{Style.RESET_ALL}")


    def nslookup_scan(ip=None, domain=None):
        if domain:
            try:
                result = dns.resolver.resolve(domain, 'A')
                for ipval in result:
                    print('IP', Fore.RED + ipval.to_text())
            except Exception as e:
                print(f"DNS Lookup failed: {e}")
        elif ip:
            try:
                domain = socket.gethostbyaddr(ip)[0]
                print(f"Domain name for {Fore.RED + ip} is {Fore.RED + domain}")
            except Exception as e:
                print(f"Reverse DNS Lookup failed: {e}")

    def reverse_dns(ip):
        try:
            host = socket.gethostbyaddr(ip)[0]
            print(f"Reverse DNS: {host}")
        except:
            print(Fore.RED + "No reverse DNS record found.")

    what_you_have()

    if input("Wanna scan more? (y/n): ").lower() != 'y':
        break