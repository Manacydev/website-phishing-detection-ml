from http.server import BaseHTTPRequestHandler
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

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
    'Symbol@':            {'label': '@ Symbol in URL',                  'detail': 'Browsers ignore everything before @ — redirects to a hidden address.'},
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
    'WebsiteForwarding':  {'label': 'Excessive Redirects',              'detail': 'Page redirects multiple times — obfuscation technique.'},
    'StatusBarCust':      {'label': 'Status Bar Manipulation',          'detail': 'JavaScript hides the true link destination in the status bar.'},
    'DisableRightClick':  {'label': 'Right-Click Disabled',             'detail': 'Prevents users from inspecting or copying links.'},
    'UsingPopupWindow':   {'label': 'Popup Windows Used',               'detail': 'Popups often display fake login screens.'},
    'IframeRedirection':  {'label': 'Hidden Iframes Detected',          'detail': 'Hidden iframes can invisibly load malicious content.'},
    'AgeofDomain':        {'label': 'Very New Domain',                  'detail': 'Domain under 6 months old — phishing sites created right before attacks.'},
    'DNSRecording':       {'label': 'No DNS Record Found',              'detail': 'No valid DNS record — suggests illegitimate domain.'},
    'WebsiteTraffic':     {'label': 'Low / No Web Traffic',             'detail': 'Very little known traffic, unlike established legitimate sites.'},
    'PageRank':           {'label': 'Low Page Rank',                    'detail': 'Low or no search engine ranking — unusual for a real website.'},
    'GoogleIndex':        {'label': 'Not Indexed by Google',            'detail': 'Not in Google search results — suspicious for any real website.'},
    'LinksPointingToPage':{'label': 'No Inbound Links',                 'detail': 'No other websites link to this page.'},
    'StatsReport':        {'label': 'Listed in Threat Reports',         'detail': 'Domain or IP flagged in known phishing/malware threat intelligence.'},
}

try:
    import joblib
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    m = joblib.load(os.path.join(base, "model", "Phishing_URL_detection.pkl"))
    importances = dict(zip(FEATURE_NAMES_ORDER, m.feature_importances_.tolist()))
except:
    importances = {}

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        info = sorted([{
            "key": f,
            "label": FEATURE_EXPLANATIONS.get(f,{}).get("label", f),
            "detail": FEATURE_EXPLANATIONS.get(f,{}).get("detail", ""),
            "importance": round(importances.get(f,0)*100, 1)
        } for f in FEATURE_NAMES_ORDER], key=lambda x: -x["importance"])
        self._respond(200, info)

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
        self.send_header('Access-Control-Allow-Methods', 'GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')