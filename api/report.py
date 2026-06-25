from http.server import BaseHTTPRequestHandler
import json

class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        data = json.loads(self.rfile.read(length) or b'{}')
        url = data.get("url", "").strip()
        if not url:
            self._respond(400, {"status": "error", "message": "No URL"})
            return
        print(f"[REPORT] {url}")
        self._respond(200, {"status": "success", "message": "Thank you for reporting."})

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
