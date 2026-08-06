import re
from urllib.parse import urlparse

def extract_features(url):

    parsed = urlparse(url)

    url_length = len(url)

    keywords = ["login","verify","secure","account","update"]
    keyword_count = sum(word in url.lower() for word in keywords)

    subdomains = parsed.netloc.count(".") - 1
    if subdomains < 0:
        subdomains = 0

    has_ip = 1 if re.search(r"\d+\.\d+\.\d+\.\d+", parsed.netloc) else 0

    special_chars = sum(url.count(c) for c in ["@","?","-","=","_"])

    return [[url_length, keyword_count, subdomains, has_ip, special_chars]]