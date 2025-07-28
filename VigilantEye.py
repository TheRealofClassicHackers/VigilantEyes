import os
import sys
import re
import requests
import socket
import time
import getpass
import json
from urllib.parse import urlparse
from colorama import Fore, Style, init
from functools import lru_cache
import ipaddress
import phonenumbers
from email_validator import validate_email, EmailNotValidError
import dns.resolver
from scapy.all import traceroute
from OpenSSL import crypto
from bs4 import BeautifulSoup
import usaddress
import bitcoinlib
from exif import Image as ExifImage
from PyPDF2 import PdfReader
import hashlib
try:
    import whois
except ImportError:
    whois = None
try:
    from mac_vendor_lookup import MacLookup
except ImportError:
    MacLookup = None
try:
    from sherlock import sherlock
except ImportError:
    sherlock = None

# Initialize colorama
init(autoreset=True)

def clear_screen():
    """Clear screen for mobile and desktop compatibility"""
    os.system('cls' if os.name == 'nt' else 'clear')

def loading_animation(message, duration=2):
    """Display a loading animation"""
    frames = ['|', '/', '-', '\\']
    print(Fore.LIGHTCYAN_EX + message, end=" ")
    for _ in range(duration * 4):
        print(Fore.LIGHTYELLOW_EX + frames[_ % 4], end="\r")
        time.sleep(0.25)
    print("\r" + " " * 50 + "\r", end="")

def show_disclaimer():
    """Display disclaimer banner for 7 seconds"""
    clear_screen()
    print(Fore.RED + r"""
    ╔════════════════════════════════════════════════════╗
    ║                   DISCLAIMER                       ║
    ║ This tool is for ethical information gathering only.║
    ║ Use only with permission or on public data.        ║
    ║ Unauthorized use may violate laws. T.R.C.H is not   ║
    ║ responsible for misuse. Proceed with caution.       ║
    ╚════════════════════════════════════════════════════╝
    """)
    time.sleep(7)
    clear_screen()

def authenticate():
    """Password authentication with 3-attempt limit"""
    max_attempts = 3
    correct_password = "P@55word"
    
    for attempt in range(max_attempts):
        clear_screen()
        print(Fore.LIGHTCYAN_EX + "[*] VigilantEye Authentication")
        password = getpass.getpass(Fore.LIGHTBLUE_EX + "[?] Enter password: ")
        
        if password == correct_password:
            clear_screen()
            print(Fore.GREEN + "[+] Authentication Verified. Happy Hacking!")
            loading_animation("Initializing VigilantEye", 2)
            return True
        else:
            print(Fore.RED + f"[!] Incorrect password. {max_attempts - attempt - 1} attempts remaining.")
            time.sleep(1)
    
    clear_screen()
    print(Fore.RED + "[!] Too many failed attempts.")
    print(Fore.YELLOW + "[!] We see you're having some problem with the password.")
    print(Fore.YELLOW + "[!] Redirecting to our Facebook page to request the tool password...")
    print(Fore.LIGHTBLUE_EX + "https://www.facebook.com/profile.php?id=61555424416864")
    time.sleep(3)
    sys.exit(1)

class VigilantEye:
    def __init__(self):
        self.session = requests.Session()
        self.results = []
        self.low_data_mode = False
        self.target_history = []
        self.configure_session()
        # Placeholder local databases (assumed to be JSON files)
        self.disposable_emails = {"mailinator.com", "tempmail.com"}  # Example
        self.cve_database = {"VendorX": ["CVE-2023-1234"]}  # Example
        self.crypto_blacklist = {"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa": "Scam"}  # Example

    def configure_session(self):
        """Configure session for mobile compatibility"""
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Linux; Android 12; Mobile) VigilantEye/1.0',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Cache-Control': 'max-age=0'
        })
        self.session.timeout = 8
        retries = requests.adapters.Retry(total=3, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
        self.session.mount('http://', requests.adapters.HTTPAdapter(max_retries=retries))
        self.session.mount('https://', requests.adapters.HTTPAdapter(max_retries=retries))

    def toggle_low_data_mode(self, enabled):
        """Toggle low data mode"""
        self.low_data_mode = enabled
        self.session.headers.update({
            'Accept-Encoding': 'gzip, deflate' if enabled else 'gzip',
            'User-Agent': 'Mozilla/5.0 (Linux; Android 12; Mobile; LowData) VigilantEye/1.0' if enabled else 'Mozilla/5.0 (Linux; Android 12; Mobile) VigilantEye/1.0'
        })

    def validate_input(self, input_type, value):
        """Validate input based on type"""
        try:
            if input_type == "ip":
                ip = ipaddress.ip_address(value)
                return isinstance(ip, ipaddress.IPv4Address) or isinstance(ip, ipaddress.IPv6Address)
            elif input_type == "email":
                validate_email(value, check_deliverability=False)
                return True
            elif input_type == "phone":
                parsed = phonenumbers.parse(value, None)
                return phonenumbers.is_valid_number(parsed)
            elif input_type == "domain":
                return bool(re.match(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$", value))
            elif input_type == "username":
                return bool(re.match(r"^[a-zA-Z0-9._-]{3,}$", value))
            elif input_type == "social_media":
                return bool(re.match(r"^https?://(www\.)?(twitter|linkedin|instagram)\.com/", value))
            elif input_type == "address":
                parsed = usaddress.tag(value)
                return parsed[1] == "Street Address"
            elif input_type == "mac":
                return bool(re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", value))
            elif input_type == "crypto":
                try:
                    bitcoinlib.keys.Address(value)
                    return True
                except:
                    return False
            elif input_type == "file":
                return os.path.isfile(value)
            return False
        except (ValueError, EmailNotValidError, phonenumbers.NumberParseException):
            return False

    @lru_cache(maxsize=10)
    def gather_ip_info(self, ip):
        """Gather information about an IP address"""
        result = {"type": "ip", "value": ip, "data": {}, "error": None}
        loading_animation(f"Gathering info for IP {ip}")
        
        try:
            ip_addr = ipaddress.ip_address(ip)
            result["data"] = {
                "type": "Public" if ip_addr.is_global else "Private",
                "version": "IPv4" if ip_addr.version == 4 else "IPv6",
                "network": str(ipaddress.ip_network(ip + "/24", strict=False)) if ip_addr.version == 4 else "N/A",
                "reverse_dns": "None",
                "open_ports": [],
                "service_versions": [],
                "as_info": "Not implemented",
                "traceroute": [],
                "firewall_detected": False,
                "geoip": "Offline GeoIP not available"
            }
            
            # Reverse DNS
            try:
                hostname, _, _ = socket.gethostbyaddr(ip)
                result["data"]["reverse_dns"] = hostname
            except socket.herror:
                pass
            
            # Port scanning
            common_ports = [80, 443, 22, 21, 25, 3389, 445, 3306] if not self.low_data_mode else [80, 443]
            for port in common_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result_code = sock.connect_ex((ip, port))
                if result_code == 0:
                    result["data"]["open_ports"].append(port)
                    try:
                        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner = sock.recv(1024).decode(errors='ignore')
                        result["data"]["service_versions"].append(f"Port {port}: {banner.splitlines()[0]}")
                    except:
                        result["data"]["service_versions"].append(f"Port {port}: No banner")
                elif result_code == 113:
                    result["data"]["firewall_detected"] = True
                sock.close()
            
            # Traceroute (limited in low data mode)
            if not self.low_data_mode:
                try:
                    res, _ = traceroute(ip, maxttl=5, verbose=0)
                    result["data"]["traceroute"] = [hop[1][0] for hop in res.get_trace().get(ip, [])]
                except Exception:
                    pass

        except Exception as e:
            result["error"] = f"Unexpected error: {str(e)}"
        
        self.results.append(result)
        return result

    @lru_cache(maxsize=10)
    def gather_email_info(self, email):
        """Gather information about an email address"""
        result = {"type": "email", "value": email, "data": {}, "error": None}
        loading_animation(f"Gathering info for email {email}")
        
        try:
            validation = validate_email(email, check_deliverability=True)
            domain = email.split("@")[1]
            result["data"] = {
                "valid_format": True,
                "normalized": validation.normalized,
                "mx_records": [],
                "spf_records": [],
                "dmarc_records": [],
                "smtp_exists": False,
                "disposable": domain in self.disposable_emails,
                "whois_registrar": "None",
                "whois_creation": "None",
                "usernames": []
            }
            
            # DNS records
            for record_type in ['MX', 'TXT']:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    if record_type == 'MX':
                        result["data"]["mx_records"] = [str(rdata) for rdata in answers]
                    elif record_type == 'TXT':
                        for rdata in answers:
                            text = str(rdata)
                            if "spf" in text.lower():
                                result["data"]["spf_records"].append(text)
                            if "dmarc" in text.lower():
                                result["data"]["dmarc_records"].append(text)
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    pass
            
            # SMTP verification (lightweight, ethical)
            try:
                mx = result["data"]["mx_records"][0].split()[-1] if result["data"]["mx_records"] else None
                if mx:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.connect((mx, 25))
                        sock.recv(1024)
                        sock.send(f"VRFY {email}\r\n".encode())
                        response = sock.recv(1024).decode(errors='ignore')
                        result["data"]["smtp_exists"] = "250" in response
            except:
                pass
            
            # WHOIS
            if whois:
                try:
                    w = whois.whois(domain)
                    result["data"]["whois_registrar"] = w.get("registrar", "Unknown")
                    result["data"]["whois_creation"] = str(w.get("creation_date", "Unknown"))
                except:
                    pass
            
            # Username enumeration
            if sherlock:
                result["data"]["usernames"] = list(sherlock(email.split("@")[0]).keys())

        except EmailNotValidError as e:
            result["error"] = f"Invalid email: {str(e)}"
        except Exception as e:
            result["error"] = f"Unexpected error: {str(e)}"
        
        self.results.append(result)
        return result

    @lru_cache(maxsize=10)
    def gather_phone_info(self, phone):
        """Gather information about a phone number"""
        result = {"type": "phone", "value": phone, "data": {}, "error": None}
        loading_animation(f"Gathering info for phone {phone}")
        
        try:
            parsed = phonenumbers.parse(phone, None)
            if not phonenumbers.is_valid_number(parsed):
                result["error"] = "Invalid phone number"
                return result
            
            result["data"] = {
                "country": phonenumbers.region_code_for_number(parsed),
                "national_format": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL),
                "type": phonenumbers.number_type(parsed),
                "timezone": phonenumbers.timezone.time_zones_for_number(parsed),
                "carrier": "Unknown",
                "portability": "Unknown",
                "international_format": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
                "region": "Unknown",
                "valid": phonenumbers.is_valid_number(parsed),
                "sms_gateway": False
            }
            
            try:
                import phonenumbers.carrier
                result["data"]["carrier"] = phonenumbers.carrier.name_for_number(parsed, "en")
            except:
                pass
            
            result["data"]["sms_gateway"] = "google" in result["data"]["carrier"].lower()

        except phonenumbers.NumberParseException as e:
            result["error"] = f"Invalid phone number: {str(e)}"
        except Exception as e:
            result["error"] = f"Unexpected error: {str(e)}"
        
        self.results.append(result)
        return result

    @lru_cache(maxsize=10)
    def gather_domain_info(self, domain):
        """Gather information about a domain"""
        result = {"type": "domain", "value": domain, "data": {}, "error": None}
        loading_animation(f"Gathering info for domain {domain}")
        
        try:
            if not self.validate_input("domain", domain):
                result["error"] = "Invalid domain format"
                return result
            
            result["data"] = {
                "a_records": [],
                "mx_records": [],
                "ns_records": [],
                "txt_records": [],
                "cname_records": [],
                "whois_registrar": "None",
                "whois_creation": "None",
                "whois_expiration": "None",
                "subdomains": [],
                "ssl_info": {}
            }
            
            # DNS lookup
            for record_type in ['A', 'MX', 'NS', 'TXT', 'CNAME']:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    result["data"][f"{record_type.lower()}_records"] = [str(rdata) for rdata in answers]
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    pass
            
            # WHOIS
            if whois:
                try:
                    w = whois.whois(domain)
                    result["data"]["whois_registrar"] = w.get("registrar", "Unknown")
                    result["data"]["whois_creation"] = str(w.get("creation_date", "Unknown"))
                    result["data"]["whois_expiration"] = str(w.get("expiration_date", "Unknown"))
                except:
                    pass
            
            # Subdomain enumeration
            common_subdomains = ['www', 'mail', 'ftp', 'blog', 'shop', 'api', 'admin', 'dev'] if not self.low_data_mode else ['www']
            for sub in common_subdomains:
                try:
                    sub_domain = f"{sub}.{domain}"
                    socket.gethostbyname(sub_domain)
                    result["data"]["subdomains"].append(sub_domain)
                except socket.gaierror:
                    continue
            
            # SSL/TLS
            try:
                cert = crypto.load_certificate(crypto.FILETYPE_PEM, requests.get(f"https://{domain}", timeout=5).text)
                result["data"]["ssl_info"] = {
                    "issuer": cert.get_issuer().CN,
                    "expiry": cert.get_notAfter().decode()
                }
            except:
                result["data"]["ssl_info"] = {"status": "No SSL or error"}

        except Exception as e:
            result["error"] = f"Unexpected error: {str(e)}"
        
        self.results.append(result)
        return result

    @lru_cache(maxsize=10)
    def gather_username_info(self, username):
        """Gather information about a username"""
        result = {"type": "username", "value": username, "data": {}, "error": None}
        loading_animation(f"Gathering info for username {username}")
        
        try:
            if not self.validate_input("username", username):
                result["error"] = "Invalid username format"
                return result
            
            result["data"] = {
                "twitter": False,
                "github": False,
                "linkedin": False,
                "instagram": False,
                "email": "None",
                "website": "None",
                "creation_date": "Unknown",
                "location": "Unknown",
                "bio": "Unknown",
                "leaked_credentials": []
            }
            
            if sherlock:
                platforms = sherlock(username)
                for platform in ["Twitter", "GitHub", "LinkedIn", "Instagram"]:
                    result["data"][platform.lower()] = bool(platforms.get(platform))

        except Exception as e:
            result["error"] = f"Unexpected error: {str(e)}"
        
        self.results.append(result)
        return result

    @lru_cache(maxsize=10)
    def gather_social_media_info(self, url):
        """Gather information from a social media profile URL"""
        result = {"type": "social_media", "value": url, "data": {}, "error": None}
        loading_animation(f"Gathering info for social media {url}")
        
        try:
            if not self.validate_input("social_media", url):
                result["error"] = "Invalid social media URL"
                return result
            
            response = self.session.get(url, timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')
            platform = urlparse(url).netloc.split('.')[1]
            result["data"] = {
                "username": "Unknown",
                "platform": platform,
                "location": "Unknown",
                "bio": "Unknown",
                "website": "None",
                "email": "None",
                "post_count": 0,
                "creation_date": "Unknown",
                "verified": False,
                "follower_count": 0
            }
            
            # Basic scraping (platform-specific)
            if platform == "twitter":
                result["data"]["username"] = soup.find("meta", {"name": "twitter:creator"})["content"] if soup.find("meta", {"name": "twitter:creator"}) else "Unknown"
            elif platform == "linkedin":
                result["data"]["bio"] = soup.find("div", {"class": "about"}) or "Unknown"

        except Exception as e:
            result["error"] = f"Unexpected error: {str(e)}"
        
        self.results.append(result)
        return result

    @lru_cache(maxsize=10)
    def gather_address_info(self, address):
        """Gather information about a physical address"""
        result = {"type": "address", "value": address, "data": {}, "error": None}
        loading_animation(f"Gathering info for address {address}")
        
        try:
            parsed, addr_type = usaddress.tag(address)
            if addr_type != "Street Address":
                result["error"] = "Invalid address format"
                return result
            
            result["data"] = {
                "components": parsed,
                "country": "US",
                "valid": True,
                "geolocation": "Offline GeoIP not available",
                "isps": "Unknown",
                "address_type": addr_type,
                "postal_format": parsed.get("ZipCode", "Unknown"),
                "region": parsed.get("StateName", "Unknown"),
                "timezone": "Unknown",
                "landmarks": "None"
            }

        except Exception as e:
            result["error"] = f"Unexpected error: {str(e)}"
        
        self.results.append(result)
        return result

    @lru_cache(maxsize=10)
    def gather_mac_info(self, mac):
        """Gather information about a MAC address"""
        result = {"type": "mac", "value": mac, "data": {}, "error": None}
        loading_animation(f"Gathering info for MAC {mac}")
        
        try:
            if not self.validate_input("mac", mac):
                result["error"] = "Invalid MAC address format"
                return result
            
            result["data"] = {
                "vendor": "Unknown",
                "valid": True,
                "device_type": "Unknown",
                "interface_type": "Unknown",
                "vulnerabilities": [],
                "oui_registration": "Unknown",
                "oui_organization": "Unknown",
                "randomized": mac.startswith(("02:", "06:", "0A:", "0E:")),
                "associated_ip": "None",
                "network_context": "None"
            }
            
            if MacLookup:
                result["data"]["vendor"] = MacLookup().lookup(mac)

        except Exception as e:
            result["error"] = f"Unexpected error: {str(e)}"
        
        self.results.append(result)
        return result

    @lru_cache(maxsize=10)
    def gather_crypto_info(self, address):
        """Gather information about a cryptocurrency address"""
        result = {"type": "crypto", "value": address, "data": {}, "error": None}
        loading_animation(f"Gathering info for crypto address {address}")
        
        try:
            if not self.validate_input("crypto", address):
                result["error"] = "Invalid crypto address"
                return result
            
            addr = bitcoinlib.keys.Address(address)
            result["data"] = {
                "valid": True,
                "blockchain": addr.network.name,
                "transaction_count": 0,
                "balance": 0,
                "first_tx_date": "Unknown",
                "last_tx_date": "Unknown",
                "wallet": "Unknown",
                "blacklisted": address in self.crypto_blacklist,
                "format": addr.format,
                "network": "Mainnet"
            }

        except Exception as e:
            result["error"] = f"Unexpected error: {str(e)}"
        
        self.results.append(result)
        return result

    @lru_cache(maxsize=10)
    def gather_file_info(self, file_path):
        """Gather information from a file's metadata"""
        result = {"type": "file", "value": file_path, "data": {}, "error": None}
        loading_animation(f"Gathering info for file {file_path}")
        
        try:
            if not self.validate_input("file", file_path):
                result["error"] = "Invalid file path"
                return result
            
            result["data"] = {
                "file_type": os.path.splitext(file_path)[1][1:].upper(),
                "author": "Unknown",
                "creation_date": "Unknown",
                "modification_date": "Unknown",
                "gps_coordinates": "None",
                "embedded_links": [],
                "hash_sha256": "",
                "software": "Unknown",
                "size": os.path.getsize(file_path),
                "embedded_email": "None"
            }
            
            if file_path.lower().endswith(".jpg"):
                with open(file_path, "rb") as f:
                    img = ExifImage(f)
                    if hasattr(img, "datetime"):
                        result["data"]["creation_date"] = img.datetime
                    if hasattr(img, "gps_latitude"):
                        result["data"]["gps_coordinates"] = (img.gps_latitude, img.gps_longitude)
            elif file_path.lower().endswith(".pdf"):
                with open(file_path, "rb") as f:
                    pdf = PdfReader(f)
                    meta = pdf.metadata
                    result["data"]["author"] = meta.get("/Author", "Unknown")
                    result["data"]["creation_date"] = meta.get("/CreationDate", "Unknown")
                    result["data"]["software"] = meta.get("/Producer", "Unknown")
            
            # File hash
            with open(file_path, "rb") as f:
                result["data"]["hash_sha256"] = hashlib.sha256(f.read()).hexdigest()

        except Exception as e:
            result["error"] = f"Unexpected error: {str(e)}"
        
        self.results.append(result)
        return result

class VigilantEyeInterface:
    def __init__(self):
        show_disclaimer()
        if not authenticate():
            sys.exit(1)
        self.recon = VigilantEye()
        self.clear_screen()
        self.show_banner()

    def clear_screen(self):
        """Clear screen for clean display"""
        clear_screen()

    def show_banner(self):
        """VigilantEye banner with slogan"""
        self.clear_screen()
        print(Fore.RED + r"""
    ╔════════════════════════════════════╗
    ║ __      ___       _ _              ║
    ║ \ \    / (_)     (_) |             ║
    ║  \ \  / / _ _ __  _| |__   __ _   ║
    ║   \ \/ / | | '_ \| | '_ \ / _` |  ║
    ║    \  /  | | | | | | | | | (_| |  ║
    ║     \/   |_|_| |_|_|_| |_|__,_|   ║
    ╚════════════════════════════════════╝
        """)
        print(Fore.LIGHTCYAN_EX + "  VigilantEye v2.0 - by T.R.C.H")
        print(Fore.LIGHTGREEN_EX + "  Seek the Truth, Uncover the Hidden")
        print(Fore.LIGHTBLACK_EX + "  Mobile-Optimized Info Gathering\n")

    def show_menu(self):
        """Touch-friendly menu"""
        menu = [
            ("1", "Set Target"),
            ("2", "Show Recent Targets"),
            ("3", "Gather IP Info"),
            ("4", "Gather Email Info"),
            ("5", "Gather Phone Info"),
            ("6", "Gather Domain Info"),
            ("7", "Gather Username Info"),
            ("8", "Gather Social Media Info"),
            ("9", "Gather Address Info"),
            ("10", "Gather MAC Address Info"),
            ("11", "Gather Crypto Address Info"),
            ("12", "Gather File Metadata"),
            ("13", "Toggle Low Data Mode"),
            ("14", "View Results"),
            ("0", "Exit")
        ]
        print(Fore.LIGHTWHITE_EX + "┌" + "─"*34 + "┐")
        for num, text in menu:
            print(Fore.LIGHTWHITE_EX + "│ " + 
                  f"{Fore.LIGHTRED_EX}{num.ljust(2)}{Fore.LIGHTWHITE_EX} {Fore.LIGHTGREEN_EX}{text.ljust(30)}" + 
                  Fore.LIGHTWHITE_EX + "│")
        print(Fore.LIGHTWHITE_EX + "└" + "─"*34 + "┘")

    def touch_input(self, prompt):
        """Mobile-friendly input"""
        print(Fore.LIGHTBLUE_EX + f"[?] {prompt}: ", end="")
        try:
            user_input = input().strip()
            if not user_input:
                print(Fore.YELLOW + "[!] Input cannot be empty")
                return None
            print(Fore.LIGHTBLACK_EX + "[*] Input received")
            return user_input
        except KeyboardInterrupt:
            print(Fore.RED + "\n[!] Operation cancelled")
            sys.exit(1)

    def set_target(self):
        """Set and validate target"""
        self.clear_screen()
        self.show_banner()
        target = self.touch_input("Enter target (IP, Email, Phone, Domain, Username, Social Media URL, Address, MAC, Crypto, File)")
        if not target:
            return
        
        target_type = None
        for t in ["ip", "email", "phone", "domain", "username", "social_media", "address", "mac", "crypto", "file"]:
            if self.recon.validate_input(t, target):
                target_type = t
                break
        
        if target_type:
            if (target_type, target) not in self.recon.target_history:
                self.recon.target_history.append((target_type, target))
                if len(self.recon.target_history) > 5:
                    self.recon.target_history.pop(0)
            print(Fore.GREEN + f"[+] Target set: {target} ({target_type})")
        else:
            print(Fore.RED + "[!] Invalid target format")

    def show_recent_targets(self):
        """Show recent targets"""
        self.clear_screen()
        self.show_banner()
        if not self.recon.target_history:
            print(Fore.YELLOW + "[!] No recent targets")
            return
        print(Fore.LIGHTCYAN_EX + "[*] Recent Targets:")
        for i, (t_type, target) in enumerate(self.recon.target_history, 1):
            print(Fore.LIGHTGREEN_EX + f"  {i}. {target} ({t_type})")
        choice = self.touch_input("Select a target number (or Enter to cancel)")
        if choice and choice.isdigit() and 1 <= int(choice) <= len(self.recon.target_history):
            print(Fore.GREEN + f"[+] Selected target: {self.recon.target_history[int(choice) - 1][1]}")

    def gather_info(self, method, input_type):
        """Generic method to gather info"""
        self.clear_screen()
        self.show_banner()
        target = self.touch_input(f"Enter {input_type} to scan")
        if not target or not self.recon.validate_input(input_type, target):
            print(Fore.RED + f"[!] Invalid {input_type} format")
            return
        result = method(target)
        self.display_result(result)

    def display_result(self, result):
        """Display a single result"""
        print(Fore.LIGHTCYAN_EX + f"[*] Results for {result['type']}: {result['value']}")
        if result["error"]:
            print(Fore.RED + f"[!] Error: {result['error']}")
        else:
            for key, value in result["data"].items():
                print(Fore.LIGHTGREEN_EX + f"  {key.capitalize()}:")
                if isinstance(value, list):
                    for item in value:
                        print(Fore.LIGHTWHITE_EX + f"    - {item}")
                elif isinstance(value, dict):
                    for k, v in value.items():
                        print(Fore.LIGHTWHITE_EX + f"    {k}: {v}")
                elif isinstance(value, tuple):
                    print(Fore.LIGHTWHITE_EX + f"    {value}")
                else:
                    print(Fore.LIGHTWHITE_EX + f"    {value}")
        time.sleep(1)
        def show_results(self):
        	 """Display all results"""
        	 self.clear_screen()
             self.show_banner()
             if not self.recon.results:
            print(Fore.YELLOW + "[!] No results available")
            return
            print(Fore.LIGHTCYAN_EX + "[*] All Results:")
           for i, result in enumerate(self.recon.results, 1):
            print(Fore.LIGHTWHITE_EX + f"  {i}. {result['type'].capitalize()}: {result['value']}")
            if result["error"]:
                print(Fore.RED + f"    Error: {result['error']}")
            else:
                for key, value in result["data"].items():
                    print(Fore.LIGHTGREEN_EX + f"    {key.capitalize()}:")
                    if isinstance(value, list):
                        for item in value:
                            print(Fore.LIGHTWHITE_EX + f"      - {item}")
                    elif isinstance(value, dict):
                        for k, v in value.items():
                            print(Fore.LIGHTWHITE_EX + f"      {k}: {v}")
                    elif isinstance(value, tuple):
                        print(Fore.LIGHTWHITE_EX + f"      {value}")
                    else:
                        print(Fore.LIGHTWHITE_EX + f"      {value}")

    def run(self):
        """Main application loop"""
        while True:
            self.clear_screen()
            self.show_banner()
            self.show_menu()
            choice = self.touch_input("Select option")
            if not choice:
                continue

            if choice == "1":
                self.set_target()
            elif choice == "2":
                self.show_recent_targets()
            elif choice == "3":
                self.gather_info(self.recon.gather_ip_info, "ip")
            elif choice == "4":
                self.gather_info(self.recon.gather_email_info, "email")
            elif choice == "5":
                self.gather_info(self.recon.gather_phone_info, "phone")
            elif choice == "6":
                self.gather_info(self.recon.gather_domain_info, "domain")
            elif choice == "7":
                self.gather_info(self.recon.gather_username_info, "username")
            elif choice == "8":
                self.gather_info(self.recon.gather_social_media_info, "social_media")
            elif choice == "9":
                self.gather_info(self.recon.gather_address_info, "address")
            elif choice == "10":
                self.gather_info(self.recon.gather_mac_info, "mac")
            elif choice == "11":
                self.gather_info(self.recon.gather_crypto_info, "crypto")
            elif choice == "12":
                self.gather_info(self.recon.gather_file_info, "file")
            elif choice == "13":
                self.toggle_low_data()
            elif choice == "14":
                self.show_results()
            elif choice == "0":
                print(Fore.RED + "[+] Exiting...")
                sys.exit(0)
            else:
                print(Fore.RED + "[!] Invalid option")
            
            input(Fore.LIGHTBLACK_EX + "\n[Press Enter to continue...")

if __name__ == "__main__":
    try:
        app = VigilantEyeInterface()
        app.run()
    except KeyboardInterrupt:
        clear_screen()
        print(Fore.RED + "\n[!] Closed by user")
        sys.exit(1)
Key Features

    