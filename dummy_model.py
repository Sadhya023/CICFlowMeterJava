#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler, HTTPServer
import json

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('content-length', 0))
        body = self.rfile.read(length).decode('utf-8')
        print('\n==== Received POST %s ====' % self.path)
        try:
            parsed = json.loads(body)
            print(json.dumps(parsed, indent=2))
        except Exception:
            print(body)
        self.send_response(200)
        self.end_headers()

    def log_message(self, format, *args):
        # suppress default logging
        pass

if __name__ == '__main__':
    port = 9101
    print('Dummy model listening on http://0.0.0.0:%d/predict/buffered' % port)
    server = HTTPServer(('0.0.0.0', port), Handler)
    server.serve_forever()
