import requests
import whois
import ssl
import socket
from bs4 import BeautifulSoup
from datetime import datetime
from urllib.parse import urlparse


def is_reachable(url):
    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        r = requests.get(url, headers=headers, timeout=5)
        return r.status_code < 500
    except:
        return False


def check_redirects(url):
    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        r = requests.get(url, headers=headers, allow_redirects=True, timeout=5)
        return len(r.history)
    except:
        return 0


def check_domain_age(url):
    try:
        domain = urlparse(url).netloc
        w = whois.whois(domain)
        creation = w.creation_date

        if isinstance(creation, list):
            creation = creation[0]

        age = (datetime.now() - creation).days
        return age
    except:
        return None


def check_ssl(url):
    try:
        hostname = urlparse(url).netloc
        context = ssl.create_default_context()

        with socket.create_connection((hostname,443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                ssock.getpeercert()

        return True
    except:
        return False


def suspicious_tld(url):

    bad = [".xyz",".top",".tk",".ml",".cf",".gq",".click",".work"]

    for tld in bad:
        if url.endswith(tld):
            return True

    return False


def brand_impersonation(url):

    brands = ["google","amazon","facebook","paytm","bank","apple","microsoft"]
    keywords = ["login","verify","secure","account"]

    brand = any(b in url.lower() for b in brands)
    keyword = any(k in url.lower() for k in keywords)

    return brand and keyword


def detect_login_form(url):

    try:
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.text,"html.parser")

        return soup.find("input",{"type":"password"}) is not None

    except:
        return False


def suspicious_hosting(url):

    bad_hosts = [
        "onrender.com",
        "vercel.app",
        "netlify.app",
        "github.io",
        "pages.dev"
    ]

    for host in bad_hosts:
        if host in url:
            return True

    return False


# -----------------------------
# NEW FEATURES
# -----------------------------

def detect_download(url):

    dangerous = [".exe",".zip",".rar",".apk",".bat",".msi"]

    for ext in dangerous:
        if url.lower().endswith(ext):
            return True

    return False


def detect_threat_types(url, login_page, bad_host, brand_fake, download):

    threats = []

    if login_page:
        threats.append("Credential Harvesting")

    if brand_fake:
        threats.append("Brand Impersonation")

    if bad_host:
        threats.append("Suspicious Hosting")

    if download:
        threats.append("Malware Distribution")

    if not threats:
        threats.append("No major threat indicators")

    return threats


def generate_ai_explanation(domain_age, login_page, bad_host, brand_fake):

    reasons = []

    if domain_age and domain_age < 30:
        reasons.append("Domain registered very recently")

    if login_page:
        reasons.append("Login form detected on webpage")

    if brand_fake:
        reasons.append("Brand impersonation pattern detected")

    if bad_host:
        reasons.append("Hosted on suspicious free hosting platform")

    if not reasons:
        reasons.append("No strong phishing indicators detected")

    return reasons


def get_ip_location(url):

    try:
        domain = urlparse(url).netloc
        ip = socket.gethostbyname(domain)

        api = f"http://ip-api.com/json/{ip}"
        res = requests.get(api).json()

        return {
            "ip": ip,
            "country": res.get("country"),
            "city": res.get("city")
        }

    except:
        return None