"""Static HTTP decoys. Request content is data, never a template or executable."""
import base64
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit, parse_qs
from core.network import BoundedThreadingMixIn

LOGIN = b'''<!doctype html><html><head><title>Administration Login</title></head>
<body><h1>Administration</h1><form method="post"><label>Username
<input name="username" autocomplete="username"></label><label>Password
<input type="password" name="password" autocomplete="current-password"></label>
<button type="submit">Log In</button></form></body></html>'''


class DecoyHandler(BaseHTTPRequestHandler):
    server_version = 'Apache/2.4.52 (Ubuntu)'
    sys_version = ''
    protocol_version = 'HTTP/1.0'

    def setup(self):
        super().setup()
        self.connection.settimeout(self.server.config['timeout'])

    def log_message(self, format, *args):
        pass  # Never render attacker-controlled terminal escapes.

    def handle_decoy(self):
        lengths = self.headers.get_all('Content-Length', [])
        body = b''
        status = 200
        limit = self.server.config['max_body_bytes']
        try:
            if self.headers.get('Transfer-Encoding'):
                status = 501
            elif len(lengths) > 1:
                status = 400
            else:
                length = int(lengths[0]) if lengths else 0
                if length < 0:
                    status = 400
                elif length > limit:
                    status = 413
                elif length:
                    body = self.rfile.read(length)
                    if len(body) != length:
                        status = 400
        except (ValueError, OSError):
            status = 400
        try:
            parsed = urlsplit(self.path)
            path, query = parsed.path, parse_qs(parsed.query, keep_blank_values=True, max_num_fields=256)
        except ValueError:
            path, query, status = self.path, {}, 400
        self.server.storage.record('http', 'request', *self.client_address,
            method=self.command, uri=self.path, path=path, query=query,
            user_agent=self.headers.get('User-Agent', ''),
            headers=list(self.headers.raw_items()), body=body.decode('utf-8', 'replace'),
            body_base64=base64.b64encode(body).decode(), response_status=status,
            body_rejected=status in (400, 413, 501))
        content_type = 'text/html; charset=utf-8'
        if status != 200:
            response = b'Request rejected\n'
        elif path in ('/admin', '/login', '/wp-login.php'):
            response = LOGIN
        elif path == '/.env':
            content_type = 'text/plain; charset=utf-8'
            response = b'APP_ENV=production\nDB_HOST=prod-db-01\nDB_USERNAME=app\nDB_PASSWORD=decoy-not-a-real-secret\n'
        elif path == '/config.json':
            content_type = 'application/json'
            response = b'{"database":{"host":"prod-db-01","user":"app","password":"decoy-only"}}'
        else:
            response = b'<html><title>Apache2 Ubuntu Default Page</title><h1>It works!</h1></html>'
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(response)))
        self.send_header('Connection', 'close')
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(response)
        self.close_connection = True

    def __getattr__(self, name):
        if name.startswith('do_'):
            return self.handle_decoy
        raise AttributeError(name)


class HTTPHoneypot(BoundedThreadingMixIn, HTTPServer):
    allow_reuse_address = True
    request_queue_size = 64

    def __init__(self, config, storage):
        self.config, self.storage = config, storage
        self.setup_limits(config['max_connections'])
        super().__init__((config['host'], config['port']), DecoyHandler)
