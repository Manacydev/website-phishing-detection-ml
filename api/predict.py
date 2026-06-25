from http.server import BaseHTTPRequestHandler
import json, sys, os, traceback
import numpy as np

# Add parent dir to path so we can import shared feature extraction
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def _load_model():
    import joblib
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    model = joblib.load(os.path.join(base, "model", "Phishing_URL_detection.pkl"))
    return model

def _load_features():
    import joblib
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return joblib.load(os.path.join(base, "model", "feature_names.pkl"))

try:
    _model = _load_model()
    _feature_names = _load_features()
    _load_error = None
except Exception as e:
    _model = None
    _feature_names = None
    _load_error = str(e)

FEATURE_NAMES_ORDER = [
    'UsingIP','LongURL','ShortURL','Symbol@','Redirecting//','PrefixSuffix-',
    'SubDomains','HTTPS','DomainRegLen','Favicon','NonStdPort','HTTPSDomainURL',
    'RequestURL','AnchorURL','LinksInScriptTags','ServerFormHandler','InfoEmail',
    'AbnormalURL','WebsiteForwarding','StatusBarCust','DisableRightClick',
    'UsingPopupWindow','IframeRedirection','AgeofDomain','DNSRecording',
    'WebsiteTraffic','PageRank','GoogleIndex','LinksPointingToPage','StatsReport'
]

FEATURE_EXPLANATIONS = {
    'UsingIP':            {'label': 'IP Address Used as Domain',        'detail': 'Raw IP instead of domain name — common phishing tactic.'},
    'LongURL':            {'label': 'Suspicious URL Length',            'detail': 'Very long URLs hide the true destination.'},
    'ShortURL':           {'label': 'URL Shortener Detected',           'detail': 'Shorteners like bit.ly mask the real destination.'},
    'Symbol@':            {'label': '@ Symbol in URL',                  'detail': 'Browsers ignore everything before @ — redirects to hidden address.'},
    'Redirecting//':      {'label': 'Multiple Redirects in URL',        'detail': 'Double slashes outside the protocol indicate suspicious redirections.'},
    'PrefixSuffix-':      {'label': 'Hyphen in Domain Name',            'detail': 'Hyphens (paypal-login.com) frequently appear in phishing domains.'},
    'SubDomains':         {'label': 'Too Many Subdomains',              'detail': 'Excessive subdomains disguise the real domain.'},
    'HTTPS':              {'label': 'No HTTPS / Insecure Connection',   'detail': 'Site does not use secure HTTPS. Legitimate sites almost always do.'},
    'DomainRegLen':       {'label': 'Short Domain Registration Period', 'detail': 'Phishing domains are typically registered for under 1 year.'},
    'Favicon':            {'label': 'External Favicon Source',          'detail': 'Favicon loaded from a different domain — may be impersonating another site.'},
    'NonStdPort':         {'label': 'Non-Standard Port Used',           'detail': 'Unusual port number, atypical for legitimate websites.'},
    'HTTPSDomainURL':     {'label': '"HTTPS" in Domain Name',           'detail': 'Having "https" in the domain itself is a deceptive tactic.'},
    'RequestURL':         {'label': 'External Resource Loading',        'detail': 'Most media loads from external domains — possible spoofed copy.'},
    'AnchorURL':          {'label': 'Suspicious Anchor Links',          'detail': 'Most links point to different domains — possible phishing replica.'},
    'LinksInScriptTags':  {'label': 'External Scripts Detected',        'detail': 'Scripts from external/untrusted domains can enable data theft.'},
    'ServerFormHandler':  {'label': 'Suspicious Form Handler',          'detail': 'Form submissions sent to external servers — credential theft risk.'},
    'InfoEmail':          {'label': 'Email Address in URL/Page',        'detail': 'mailto: links may be used to harvest user information.'},
    'AbnormalURL':        {'label': 'Domain Mismatch (WHOIS)',          'detail': 'URL domain does not match the registered WHOIS domain.'},
    'WebsiteForwarding':  {'label': 'Excessive Redirects',              'detail': 'Page redirects multiple times before loading — obfuscation technique.'},
    'StatusBarCust':      {'label': 'Status Bar Manipulation',          'detail': 'JavaScript hides the true link destination in the status bar.'},
    'DisableRightClick':  {'label': 'Right-Click Disabled',             'detail': 'Prevents users from inspecting or copying links.'},
    'UsingPopupWindow':   {'label': 'Popup Windows Used',               'detail': 'Popups often display fake login screens.'},
    'IframeRedirection':  {'label': 'Hidden Iframes Detected',          'detail': 'Hidden iframes can invisibly load malicious content.'},
    'AgeofDomain':        {'label': 'Very New Domain',                  'detail': 'Domain under 6 months old — phishing sites are created right before attacks.'},
    'DNSRecording':       {'label': 'No DNS Record Found',              'detail': 'No valid DNS record — suggests illegitimate domain.'},
    'WebsiteTraffic':     {'label': 'Low / No Web Traffic',             'detail': 'Very little known traffic, unlike established legitimate sites.'},
    'PageRank':           {'label': 'Low Page Rank',                    'detail': 'Low or no search engine ranking — unusual for a real website.'},
    'GoogleIndex':        {'label': 'Not Indexed by Google',            'detail': 'Not in Google search results — suspicious for any real website.'},
    'LinksPointingToPage':{'label': 'No Inbound Links',                 'detail': 'No other websites link to this page.'},
    'StatsReport':        {'label': 'Listed in Threat Reports',         'detail': 'Domain or IP flagged in known phishing/malware threat intelligence.'},
}

FEATURE_IMPORTANCE = dict(zip(FEATURE_NAMES_ORDER, _model.feature_importances_.tolist())) if _model else {}

def extract_features(url: str):
    import re, socket
    from urllib.parse import urlparse, urljoin
    import requests
    from bs4 import BeautifulSoup
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    features = {name: 1 for name in FEATURE_NAMES_ORDER}

    if not re.match(r"^https?://", url):
        url = "http://" + url

    parsed = urlparse(url)
    domain = parsed.netloc.split(':')[0]

    # URL-based
    try:
        socket.inet_aton(domain)
        features['UsingIP'] = -1
    except (socket.error, ValueError):
        pass

    l = len(url)
    if l > 75:      features['LongURL'] = -1
    elif l >= 54:   features['LongURL'] = 0
    if re.search(r"bit\.ly|goo\.gl|t\.co|tinyurl|ow\.ly|is\.gd", url, re.I): features['ShortURL'] = -1
    if '@' in url:  features['Symbol@'] = -1
    if url.rfind('//') > 6: features['Redirecting//'] = -1
    if '-' in domain: features['PrefixSuffix-'] = -1
    dots = domain.count('.')
    if dots > 3:    features['SubDomains'] = -1
    elif dots == 3: features['SubDomains'] = 0
    if parsed.scheme != 'https': features['HTTPS'] = -1
    if parsed.port and parsed.port not in [80, 443]: features['NonStdPort'] = -1
    if 'https' in domain.lower(): features['HTTPSDomainURL'] = -1

    # WHOIS (with timeout)
    from multiprocessing import Process, Queue
    import whois
    from datetime import datetime

    def _whois_worker(d, q):
        try: q.put(whois.whois(d))
        except: q.put(None)

    q = Queue()
    p = Process(target=_whois_worker, args=(domain, q))
    p.start(); p.join(8)
    if p.is_alive(): p.terminate(); p.join()
    w = q.get() if not q.empty() else None

    if w and w.creation_date:
        cd = (w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date)
        ed = w.expiration_date
        if ed: ed = ed[0] if isinstance(ed, list) else ed
        features['DomainRegLen'] = 1 if (ed and cd and (ed - cd).days > 365) else -1
        features['AgeofDomain']  = 1 if (datetime.now() - cd).days >= 180 else -1
        features['DNSRecording'] = 1
        wdn = w.domain_name
        if wdn:
            match = any(domain.lower() in d.lower() for d in (wdn if isinstance(wdn, list) else [wdn]))
            features['AbnormalURL'] = 1 if match else -1
        else:
            features['AbnormalURL'] = -1
    else:
        for f in ['DomainRegLen','AgeofDomain','DNSRecording','AbnormalURL']:
            features[f] = -1

    # Content-based
    try:
        hdrs = {'User-Agent': 'Mozilla/5.0'}
        resp = requests.get(url, headers=hdrs, verify=False, timeout=10)
        soup = BeautifulSoup(resp.text, 'html.parser')

        fav = soup.find("link", rel=re.compile(r'icon', re.I))
        if fav and fav.get('href') and urlparse(urljoin(url, fav['href'])).netloc not in ('', domain):
            features['Favicon'] = -1

        reqs = [t.get('src','') for t in soup.find_all(['img','video','audio'], src=True)]
        if reqs:
            ext = sum(1 for r in reqs if urlparse(urljoin(url,r)).netloc not in ('',domain))
            if ext/len(reqs) > 0.61: features['RequestURL'] = -1

        ancs = [a.get('href','') for a in soup.find_all('a', href=True)]
        if ancs:
            ext_a = sum(1 for a in ancs if urlparse(urljoin(url,a)).netloc not in ('',domain,''))
            if ext_a/len(ancs) > 0.67: features['AnchorURL'] = -1

        scrpts = soup.find_all('script', src=True)
        if scrpts:
            ext_s = sum(1 for s in scrpts if urlparse(urljoin(url,s.get('src',''))).netloc not in ('',domain))
            r = ext_s/len(scrpts)
            if r > 0.17: features['LinksInScriptTags'] = -1
            elif r > 0.11: features['LinksInScriptTags'] = 0

        for form in soup.find_all('form', action=True):
            act = form.get('action','').strip()
            if not act or act in ['#','javascript:void(0)','about:blank']:
                features['ServerFormHandler'] = -1; break
            if urlparse(urljoin(url,act)).netloc not in ('',domain):
                features['ServerFormHandler'] = 0; break

        if re.search(r'mailto:', resp.text, re.I): features['InfoEmail'] = -1
        if len(resp.history) > 1: features['WebsiteForwarding'] = -1
        if re.search(r'onmouseover\s*=\s*[\'"]window\.status', resp.text, re.I): features['StatusBarCust'] = -1
        if re.search(r'event\.button\s*==\s*2', resp.text): features['DisableRightClick'] = -1
        if re.search(r'window\.open\s*\(', resp.text): features['UsingPopupWindow'] = -1
        if soup.find_all('iframe'): features['IframeRedirection'] = -1

    except Exception:
        for f in ['Favicon','RequestURL','AnchorURL','LinksInScriptTags','ServerFormHandler',
                  'InfoEmail','WebsiteForwarding','StatusBarCust','DisableRightClick',
                  'UsingPopupWindow','IframeRedirection']:
            features[f] = -1

    if features['AgeofDomain'] == -1:
        features['WebsiteTraffic'] = -1
        features['GoogleIndex'] = -1
        features['LinksPointingToPage'] = -1

    arr = np.array([features.get(n, 1) for n in FEATURE_NAMES_ORDER]).reshape(1,-1)
    return arr, features


class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if _model is None:
            self._respond(503, {"error": f"Model not loaded: {_load_error}"})
            return
        try:
            length = int(self.headers.get('Content-Length', 0))
            body   = self.rfile.read(length)
            data   = json.loads(body)
            url    = data.get("url", "").strip()
            if not url:
                self._respond(400, {"error": "No URL provided"}); return

            import pandas as pd
            arr, features_dict = extract_features(url)
            df   = pd.DataFrame(arr, columns=FEATURE_NAMES_ORDER)
            pred = _model.predict(df)[0]
            prob = _model.predict_proba(df)[0]
            is_safe = bool(pred == 1)
            phi = int(np.where(_model.classes_ == -1)[0][0])
            phish_prob = float(prob[phi])

            flagged = [k for k,v in features_dict.items() if v == -1]
            reasons = sorted([{
                "key": f,
                "label": FEATURE_EXPLANATIONS.get(f,{}).get("label", f),
                "detail": FEATURE_EXPLANATIONS.get(f,{}).get("detail", ""),
                "importance": round(FEATURE_IMPORTANCE.get(f,0)*100, 1)
            } for f in flagged], key=lambda x: -x["importance"])

            top = sorted(FEATURE_IMPORTANCE.items(), key=lambda x: -x[1])[:8]
            risk_breakdown = [{
                "feature": FEATURE_EXPLANATIONS.get(f,{}).get("label", f),
                "importance": round(i*100, 1),
                "flagged": features_dict.get(f,1) == -1
            } for f,i in top]

            self._respond(200, {
                "is_safe": is_safe,
                "probability_unsafe": phish_prob,
                "probability_safe": float(1 - phish_prob),
                "reasons": reasons,
                "risk_breakdown": risk_breakdown,
                "total_flags": len(flagged),
                "features_checked": len(FEATURE_NAMES_ORDER)
            })
        except Exception as e:
            traceback.print_exc()
            self._respond(500, {"error": "Could not process URL"})

    def do_OPTIONS(self):
        self.send_response(200)
        self._cors(); self.end_headers()

    def _respond(self, status, body):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self._cors(); self.end_headers()
        self.wfile.write(json.dumps(body).encode())

    def _cors(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
