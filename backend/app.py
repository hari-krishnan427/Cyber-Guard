from flask import Flask, request, jsonify, render_template
import joblib
from urllib.parse import urlparse

from features import extract_features
from security_checks import *

app = Flask(__name__)

model = joblib.load("phishing_model.pkl")


# -----------------------
# SYSTEM LEVEL DOMAIN BLOCKING
# -----------------------

def block_domain(url):

    hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
    redirect_ip = "127.0.0.1"

    domain = urlparse(url).netloc

    entry = f"{redirect_ip} {domain}\n"

    try:
        with open(hosts_path, "r+") as file:
            content = file.read()

            if domain not in content:
                file.write(entry)

        print(f"[CyberGuard] Domain blocked: {domain}")

    except PermissionError:
        print("[CyberGuard] Run VS Code as Administrator to enable blocking.")


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():

    data = request.get_json()
    url = data.get("url","").strip()

    if not url:
        return jsonify({"error":"No URL provided"}),400

    if not url.startswith("http"):
        url = "http://" + url


    if not is_reachable(url):
        return jsonify({"error":"Website unreachable"}),400


    # -----------------------
    # Feature Extraction
    # -----------------------

    features = extract_features(url)
    url_length, keywords, subdomains, has_ip, special_chars = features[0]


    # -----------------------
    # Security Checks
    # -----------------------

    redirects = check_redirects(url)
    domain_age = check_domain_age(url)
    ssl_valid = check_ssl(url)

    bad_tld = suspicious_tld(url)
    brand_fake = brand_impersonation(url)
    login_page = detect_login_form(url)
    bad_host = suspicious_hosting(url)

    download = detect_download(url)


    # -----------------------
    # ML Prediction
    # -----------------------

    try:
        ml_prediction = int(model.predict(features)[0])
    except:
        ml_prediction = 0


    # -----------------------
    # Risk Scoring
    # -----------------------

    risk_score = 0

    if has_ip:
        risk_score += 30

    if keywords > 0:
        risk_score += 15

    if special_chars > 2:
        risk_score += 10

    if redirects > 2:
        risk_score += 15

    if bad_tld:
        risk_score += 20

    if brand_fake:
        risk_score += 40

    if bad_host:
        risk_score += 40

    if login_page:
        risk_score += 20

    if domain_age and domain_age < 30:
        risk_score += 20

    if not ssl_valid:
        risk_score += 10

    if ml_prediction == 1:
        risk_score += 20

    if download:
        risk_score += 40


    prediction = "PHISHING" if risk_score >= 50 else "SAFE"


    # -----------------------
    # BLOCK DOMAIN IF MALICIOUS
    # -----------------------

    if prediction == "PHISHING":
        block_domain(url)


    # -----------------------
    # NEW ENGINES
    # -----------------------

    threats = detect_threat_types(
        url,
        login_page,
        bad_host,
        brand_fake,
        download
    )

    explanation = generate_ai_explanation(
        domain_age,
        login_page,
        bad_host,
        brand_fake
    )

    location = get_ip_location(url)


    return jsonify({

        "url": url,
        "result": prediction,
        "risk_score": risk_score,

        "domain_age": domain_age,
        "ssl_valid": ssl_valid,
        "redirects": redirects,
        "login_page": login_page,

        "threat_types": threats,
        "ai_explanation": explanation,
        "location": location,

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