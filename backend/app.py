import os
import sys
from flask import Flask, request, jsonify, render_template
import joblib
from urllib.parse import urlparse

# Ensure directory is on python path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from features import extract_features
from security_checks import *

TEMPLATE_DIR = os.path.abspath(os.path.join(BASE_DIR, "../templates"))
STATIC_DIR = os.path.abspath(os.path.join(BASE_DIR, "../static"))

if not os.path.exists(TEMPLATE_DIR):
    TEMPLATE_DIR = os.path.abspath(os.path.join(BASE_DIR, "templates"))
if not os.path.exists(STATIC_DIR):
    STATIC_DIR = os.path.abspath(os.path.join(BASE_DIR, "static"))

app = Flask(__name__, template_folder=TEMPLATE_DIR, static_folder=STATIC_DIR)

model_path = os.path.join(BASE_DIR, "phishing_model.pkl")
if not os.path.exists(model_path):
    model_path = os.path.abspath(os.path.join(BASE_DIR, "../24-Hours_Hackathon/phishing_model.pkl"))

try:
    model = joblib.load(model_path)
except Exception as e:
    print("Warning: Model load error:", e)
    model = None

def block_domain(url):
    try:
        hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
        if not os.path.exists(hosts_path):
            return
        redirect_ip = "127.0.0.1"
        domain = urlparse(url).netloc
        entry = f"{redirect_ip} {domain}\n"
        with open(hosts_path, "r+") as file:
            content = file.read()
            if domain not in content:
                file.write(entry)
    except Exception:
        pass

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json() or {}
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    if not url.startswith("http"):
        url = "http://" + url

    if not is_reachable(url):
        return jsonify({"error": "Website unreachable"}), 400

    features = extract_features(url)
    url_length, keywords, subdomains, has_ip, special_chars = features[0]

    redirects = check_redirects(url)
    domain_age = check_domain_age(url)
    ssl_valid = check_ssl(url)

    bad_tld = suspicious_tld(url)
    brand_fake = brand_impersonation(url)
    login_page = detect_login_form(url)
    bad_host = suspicious_hosting(url)
    download = detect_download(url)

    ml_prediction = 0
    if model:
        try:
            ml_prediction = int(model.predict(features)[0])
        except Exception:
            ml_prediction = 0

    risk_score = 0
    if has_ip: risk_score += 30
    if keywords > 0: risk_score += 15
    if special_chars > 2: risk_score += 10
    if redirects > 2: risk_score += 15
    if bad_tld: risk_score += 20
    if brand_fake: risk_score += 40
    if bad_host: risk_score += 40
    if login_page: risk_score += 20
    if domain_age and domain_age < 30: risk_score += 20
    if not ssl_valid: risk_score += 10
    if ml_prediction == 1: risk_score += 20
    if download: risk_score += 40

    prediction = "PHISHING" if risk_score >= 50 else "SAFE"

    if prediction == "PHISHING":
        block_domain(url)

    threats = detect_threat_types(url, login_page, bad_host, brand_fake, download)
    explanation_str = generate_ai_explanation(domain_age, login_page, bad_host, brand_fake)
    
    # Format explanation as list for UI rendering
    explanation_list = [explanation_str] if isinstance(explanation_str, str) else explanation_str

    # Format location as structured object for UI rendering
    loc_str = get_ip_location(url)
    if isinstance(loc_str, dict):
        location_obj = loc_str
    elif loc_str and "," in str(loc_str):
        parts = str(loc_str).split(",", 1)
        location_obj = {"city": parts[0].strip(), "country": parts[1].strip(), "ip": urlparse(url).netloc}
    else:
        location_obj = {"city": "GLOBAL CDN", "country": "UNITED STATES", "ip": urlparse(url).netloc or "127.0.0.1"}

    return jsonify({
        "url": url,
        "result": prediction,
        "risk_score": risk_score,
        "domain_age": domain_age or 365,
        "ssl_valid": ssl_valid,
        "redirects": redirects,
        "login_page": login_page,
        "threat_types": threats,
        "ai_explanation": explanation_list,
        "location": location_obj,
        "features": {
            "length": url_length,
            "keywords": keywords,
            "subdomains": subdomains,
            "has_ip": has_ip,
            "special_chars": special_chars
        }
    })

if __name__ == "__main__":
    app.run(debug=True)
