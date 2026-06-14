from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import joblib
import numpy as np
import pandas as pd
import re
import socket
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import requests
import whois
from datetime import datetime
import time
import urllib3
import os
import traceback
#from multiprocessing import Process, Queue # For robust timeouts
from concurrent.futures import ThreadPoolExecutor, TimeoutError

app = Flask(__name__)

# --- Suppress InsecureRequestWarning ---
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ----------------------------------------------------------------------------
# | MODEL LOADING
# ----------------------------------------------------------------------------
try:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    MODEL_PATH = os.path.join(BASE_DIR, "model", "Phishing_URL_detection.pkl")
    FEATURES_PATH = os.path.join(BASE_DIR, "model", "feature_names.pkl")

    model = joblib.load(MODEL_PATH)
    feature_names = joblib.load(FEATURES_PATH)
    print(f"✅ Model loaded successfully from: {MODEL_PATH}")
    
    feature_names_order = [
        'UsingIP', 'LongURL', 'ShortURL', 'Symbol@', 'Redirecting//',
        'PrefixSuffix-', 'SubDomains', 'HTTPS', 'DomainRegLen', 'Favicon',
        'NonStdPort', 'HTTPSDomainURL', 'RequestURL', 'AnchorURL',
        'LinksInScriptTags', 'ServerFormHandler', 'InfoEmail', 'AbnormalURL',
        'WebsiteForwarding', 'StatusBarCust', 'DisableRightClick',
        'UsingPopupWindow', 'IframeRedirection', 'AgeofDomain', 'DNSRecording',
        'WebsiteTraffic', 'PageRank', 'GoogleIndex', 'LinksPointingToPage',
        'StatsReport'
    ]

except FileNotFoundError as e:
    print(f"❌ CRITICAL ERROR: Could not find model files. {e}")
    model = None
    feature_names_order = []


# ----------------------------------------------------------------------------
# | FEATURE EXTRACTION LOGIC
# ----------------------------------------------------------------------------

def _whois_target(domain, q):
    """Target function for multiprocessing to get whois info."""
    try:
        q.put(whois.whois(domain))
    except Exception:
        q.put(None)

"""def get_whois_with_timeout(domain, timeout=4):
   
    #Performs a whois lookup in a separate process to enforce a strict timeout.
    
    q = Queue()
    p = Process(target=_whois_target, args=(domain, q))
    p.start()
    p.join(timeout)
    if p.is_alive():
        p.terminate()
        p.join()
        print(f"    - 🟡 WHOIS lookup for {domain} timed out after {timeout} seconds.")
        return None
    
    result = q.get()
    if result is None:
        print(f"    - 🟡 WHOIS lookup for {domain} failed.")
    return result
"""
def whois_lookup(domain):
    """Function to execute WHOIS lookup."""
    try:
        return whois.whois(domain)
    except Exception:
        return None

def fetch_content(url, headers):
    """Function to execute HTTP request."""
    try:
        response = requests.get(
            url, 
            timeout=3, # Individual request timeout (can be shorter if needed)
            headers=headers, 
            verify=False, 
            allow_redirects=True
        )
        response.raise_for_status()
        return response
    except requests.exceptions.RequestException as e:
        print(f"    - ❌ Content fetch failed. Reason: {type(e).__name__}")
        return None
    
def extract_features(url: str):
    """
    Extracts all 30 features from a URL.
    """
    features = {name: 0 for name in feature_names_order}
    
    if not re.match(r"^(https?)://", url):
        url = "http://" + url
    
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
    except ValueError:
        for feature in feature_names_order: features[feature] = -1
        return np.array(list(features.values())).reshape(1, -1)

    if not domain:
        for feature in feature_names_order: features[feature] = -1
        return np.array(list(features.values())).reshape(1, -1)

    start_time = time.time()
    print(f"\n🚀 Starting feature extraction for: {url}")

    # --- 1. Address Bar Based Features ---
    is_ip = False
    try:
        socket.inet_aton(domain)
        features['UsingIP'], is_ip = -1, True
    except (socket.error, ValueError):
        features['UsingIP'] = 1
    features['LongURL'] = -1 if len(url) > 75 else (0 if 54 <= len(url) <= 75 else 1)
    features['ShortURL'] = -1 if re.search(r"bit\.ly|goo\.gl", url) else 1
    features['Symbol@'] = -1 if '@' in url else 1
    features['Redirecting//'] = -1 if url.rfind('//') > 6 else 1
    features['PrefixSuffix-'] = -1 if '-' in domain else 1
    dots = domain.count('.')
    features['SubDomains'] = -1 if dots > 3 else (0 if dots == 3 else 1)
    features['HTTPS'] = 1 if parsed_url.scheme == 'https' else -1
        
    # --- 2. Domain Based Features ---
    """
    w = get_whois_with_timeout(domain, timeout=2) if not is_ip and '.' in domain else None
    
    
    if w and w.creation_date and w.expiration_date:
        try:
            exp_date = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
            creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            if isinstance(exp_date, datetime) and isinstance(creation_date, datetime):
                features['DomainRegLen'] = -1 if (exp_date - creation_date).days <= 365 else 1
                features['AgeofDomain'] = -1 if (datetime.now() - creation_date).days < 180 else 1
            else:
                features['DomainRegLen'], features['AgeofDomain'] = -1, -1
        except Exception:
            features['DomainRegLen'], features['AgeofDomain'] = -1, -1
    else:
        features['DomainRegLen'], features['AgeofDomain'] = -1, -1
    
    features['DNSRecording'] = -1 if not w else 1
    """
    w, response = None, None
    # --- 3. Content and HTML Based Features ---
    """
    try:
        print(f"    - 🌐 Fetching content from {url}...")
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        response = requests.get(url, timeout=2, headers=headers, verify=False, allow_redirects=True)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        print(f"    - ✅ Content fetched successfully.")
        
        features['IframeRedirection'] = -1 if soup.find('iframe') or soup.find('frame') else 1
        features['WebsiteForwarding'] = 0 if len(response.history) <= 1 else -1

    except requests.exceptions.RequestException as e:
        print(f"    - ❌ Could not fetch content. Reason: {type(e).__name__}")
        # Mark all content-based features as suspicious (-1)
        for f in ['IframeRedirection', 'WebsiteForwarding']: features[f] = -1
    """
    # 3-second timeout for the network phase
    NETWORK_TIMEOUT = 3 
    from concurrent.futures import ThreadPoolExecutor # Ensure this is imported
    executor = ThreadPoolExecutor(max_workers=4) 
# The executor object is now available globally.
    try:
        print(f"    - 🌐 Starting concurrent network fetches with {NETWORK_TIMEOUT}s timeout...")
        
        # Future for WHOIS lookup
        whois_future = executor.submit(whois_lookup, domain)
        
        # Future for HTTP request
        headers = {'User-Agent': 'Mozilla/5.0'}
        content_future = executor.submit(fetch_content, url, headers)
        
        # Get results with an overall timeout
        w = whois_future.result(timeout=NETWORK_TIMEOUT)
        response = content_future.result(timeout=NETWORK_TIMEOUT)
        
    except TimeoutError:
        # This catches if either WHOIS or content fetch took longer than 3 seconds
        print(f"    - 🟡 Network phase timed out after {NETWORK_TIMEOUT} seconds.")
    except Exception:
        # General catch for other thread-related errors
        print("    - 🚨 An unexpected error occurred during network fetching.")

    # --- 3. Domain Based Features (using WHOIS result) ---
    is_domain_info_valid = False
    if w and w.creation_date and w.expiration_date:
        try:
            exp_date = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
            creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            if isinstance(exp_date, datetime) and isinstance(creation_date, datetime):
                features['DomainRegLen'] = -1 if (exp_date - creation_date).days <= 365 else 1
                features['AgeofDomain'] = -1 if (datetime.now() - creation_date).days < 180 else 1
                is_domain_info_valid = True
        except Exception:
            pass # Keep default -1 values on failure
    
    if not is_domain_info_valid:
        features['DomainRegLen'], features['AgeofDomain'] = -1, -1
        
    features['DNSRecording'] = -1 if not w else 1

    # --- 4. Content and HTML Based Features (using HTTP result) ---
    if response:
        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            features['IframeRedirection'] = -1 if soup.find('iframe') or soup.find('frame') else 1
            features['WebsiteForwarding'] = 0 if len(response.history) <= 1 else -1
        except Exception:
            features['IframeRedirection'], features['WebsiteForwarding'] = -1, -1
    else:
        # Mark all content-based features as suspicious (-1) if fetch failed or timed out
        features['IframeRedirection'], features['WebsiteForwarding'] = -1, -1
    # --- 4. Simulated and placeholder features (as in original) ---
    features['NonStdPort'] = 1
    features['HTTPSDomainURL'] = 1
    features['Favicon'], features['RequestURL'], features['AnchorURL'], features['LinksInScriptTags'] = 1,1,1,1
    features['ServerFormHandler'], features['InfoEmail'], features['AbnormalURL'] = 1,1,1
    features['StatusBarCust'], features['DisableRightClick'], features['UsingPopupWindow'] = 1,1,1
    features['PageRank'], features['GoogleIndex'], features['LinksPointingToPage'], features['StatsReport'] = 1,1,1,1
    features['WebsiteTraffic'] = 0 # Neutral traffic assumption

    print(f"🏁 Feature extraction finished in {time.time() - start_time:.2f} seconds.")
    return np.array([features[name] for name in feature_names_order]).reshape(1, -1)


# ----------------------------------------------------------------------------
# | FLASK ROUTES
# ----------------------------------------------------------------------------
def run_prediction_model(data):
    # Your model calculation logic goes here
    # ...
    return {'is_safe': True, 'probability_unsafe': 0.05, 'url': data.get('url')}
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/predict", methods=["POST"])

def predict():
    if not model:
        return jsonify({"error": "Model not loaded properly."}), 500
        
    url = request.get_json().get("url", "")
    if not url:
        return jsonify({"error": "No URL provided."}), 400

    try:
        features_array = extract_features(url)
        
        features_df = pd.DataFrame(features_array, columns=feature_names_order)
        # 2. Add final data cleaning/check before prediction
        features_df = features_df.fillna(-1) # Replace any NaN/missing with -1
        features_df = features_df.astype(float) # Ensure all columns are floats
        
        prediction_val = model.predict(features_df)[0]
        # ... rest of the prediction logic
        
        prediction_val = model.predict(features_df)[0]
        probabilities = model.predict_proba(features_df)[0]
        
        is_safe = bool(prediction_val == 1)
       # phishing_prob = 0.0
        try:
            phishing_class_index = np.where(model.classes_ == -1)[0][0]
            phishing_prob = probabilities[phishing_class_index]
        except (IndexError, ValueError):
          #  phishing_prob = 0.99 if not is_safe else 0.01
           is_safe = bool(prediction_val == 1)
           # Get the probability of the *predicted* class
        # Find the index corresponding to the -1 class (unsafe)
        try:
            phishing_class_index = np.where(model.classes_ == -1)[0][0]
            phishing_prob = probabilities[phishing_class_index]
        except (IndexError, ValueError):
            # Fallback: Assume the second class is the "unsafe" one if -1 isn't explicitly found
            # This is common in binary classifiers where classes_ might be [1, -1] or [0, 1]
            if is_safe:
                # If safe (1), phishing_prob is the probability of the other class
                phishing_prob = 1.0 - probabilities[np.where(model.classes_ == 1)[0][0]]
            else:
                # If unsafe (-1), phishing_prob is the probability of the unsafe class
                phishing_prob = 0.99 # Safe fallback value
        return jsonify({
            "is_safe": is_safe,
            "probability_unsafe": float(phishing_prob),
            "url": url
        })

    except Exception as e:
        print(f"--- 🚨 UNHANDLED EXCEPTION IN /predict ---")
        print(f"URL: {url}")
        traceback.print_exc()
        return jsonify({"error": f"Analysis failed due to a server error. Check logs. Detail: {type(e).__name__}"}), 500
def handle_predict():
    print("1. Request received.") 
    
    try:
        # Get JSON data from the request body
        data = request.get_json()
        
        # Extract the URL from the received data
        url = data.get('url')
        
        # Run the prediction model
        result = run_prediction_model(data) 
        
        print("2. Prediction calculated:", result) 
        
        # 🟢 CRITICAL STEP: Return the JSON response using Flask's jsonify
        return jsonify({'prediction': result}) # <-- ADD IT HERE
        
        # Flask handles the success response and closes the connection.
        
    except Exception as error:
        print("3. Prediction failed with error:", error)
        
        # 🔴 Error Response: Return a 500 status with an error message
        return jsonify({'error': 'Prediction processing failed'}), 500
"""if __name__ == "__main__":
    app.run(debug=True)"""

# app.py - Inside the final block
# app.py (Near the bottom)

if __name__ == "__main__":
    # --- IMPORTANT CHANGE ---
    # Use Waitress for production-ready, concurrent service on Windows.
    from waitress import serve
    print("Serving app with Waitress on http://127.0.0.1:5000")
    serve(app, host='0.0.0.0', port=5000, threads=8)
     # Set a thread count (e.g., 8)
    # If you must use debug mode:
    # app.run(debug=True)
# Initialize Flask
app = Flask(__name__)
# ADD THIS LINE:
CORS(app) # This enables CORS for all routes and origins