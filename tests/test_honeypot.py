import concurrent.futures
import http.client
import json
from pathlib import Path
import socket
import sqlite3
import tempfile
import threading
import unittest

import paramiko
from main import load_config
from core.storage import Storage
from core.ssh_honeypot import SSHHoneypot, load_host_key
from core.http_honeypot import HTTPHoneypot


class HoneypotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.config = load_config('config.yaml')
        self.config['storage'].update(database=str(self.root / 'events.db'), json_log=str(self.root / 'events.json'))
        self.config['ssh'].update(host='127.0.0.1', port=0, tarpit_delay=0.01,
            host_key=str(self.root / 'key'), session_timeout=3)
        self.config['http'].update(host='127.0.0.1', port=0, timeout=1)
        self.storage = Storage(self.config['storage'])
        self.servers = []

    def tearDown(self):
        for server, thread in self.servers:
            server.stop()
            thread.join(5)
            self.assertFalse(thread.is_alive())
        self.storage.close()
        self.temp.cleanup()

    def start(self, cls, service):
        server = cls(self.config[service], self.storage)
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .05})
        thread.start()
        self.servers.append((server, thread))
        return server.server_address[1]

    def events(self):
        with sqlite3.connect(self.config['storage']['database']) as db:
            return [json.loads(row[0]) for row in db.execute('SELECT event_json FROM events')]

    def test_concurrent_storage_and_json(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda n: self.storage.record('ssh', 'authentication', '127.0.0.1', n,
                username='test\n\x1b[31m', password='x'), range(100)))
        lines = Path(self.config['storage']['json_log']).read_text().splitlines()
        self.assertEqual(len(lines), 100)
        self.assertEqual(len(self.events()), 100)
        self.assertTrue(all(json.loads(line)['source']['ip'] == '127.0.0.1' for line in lines))

    def test_http_decoys_and_payload_limits(self):
        port = self.start(HTTPHoneypot, 'http')
        for path in ['/admin', '/login', '/wp-login.php', '/.env', '/config.json']:
            connection = http.client.HTTPConnection('127.0.0.1', port, timeout=3)
            connection.request('POST', path + '?a=1&a=2', body=b'password=x\x00', headers={'User-Agent': 'test-agent'})
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            self.assertTrue(response.read())
            connection.close()
        event = self.events()[0]
        self.assertEqual(event['query']['a'], ['1', '2'])
        self.assertEqual(event['body'], 'password=x\x00')
        connection = http.client.HTTPConnection('127.0.0.1', port, timeout=3)
        connection.request('POST', '/', headers={'Content-Length': '99999999'})
        self.assertEqual(connection.getresponse().status, 413)
        connection.close()

    def test_key_persistence_and_auth_rejection(self):
        port = self.start(SSHHoneypot, 'ssh')
        first = load_host_key(self.config['ssh']['host_key'])
        self.assertEqual(first.asbytes(), load_host_key(self.config['ssh']['host_key']).asbytes())
        self.assertEqual((self.root / 'key').stat().st_mode & 0o777, 0o600)
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            with self.assertRaises(paramiko.AuthenticationException):
                client.connect('127.0.0.1', port=port, username='root', password='password',
                               look_for_keys=False, allow_agent=False, timeout=3)
        finally:
            client.close()
        event = self.events()[0]
        self.assertEqual(event['username'], 'root')
        self.assertEqual(event['password'], 'password')
        self.assertTrue(event['client_banner'].startswith('SSH-2.0-'))

    def test_fake_shell_never_executes(self):
        self.config['ssh']['fake_shell'] = True
        port = self.start(SSHHoneypot, 'ssh')
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect('127.0.0.1', port=port, username='root', password='x',
                           look_for_keys=False, allow_agent=False, timeout=3)
            shell = client.invoke_shell()
            shell.settimeout(3)
            shell.recv(4096)
            marker = self.root / 'executed'
            shell.sendall(f'touch {marker}\nexit\n'.encode())
            while shell.recv(4096):
                pass
            self.assertFalse(marker.exists())
            self.assertTrue(any(e['kind'] == 'command' and 'high_interest' in e['tags'] for e in self.events()))
        finally:
            client.close()

    def test_connection_limit_and_idle_shutdown(self):
        self.config['http']['max_connections'] = 1
        port = self.start(HTTPHoneypot, 'http')
        first = socket.create_connection(('127.0.0.1', port))
        first.sendall(b'GET / HTTP/1.0\r\n')
        # Stop must interrupt clients that have not finished sending headers.
        server, thread = self.servers.pop()
        server.stop()
        thread.join(3)
        self.assertFalse(thread.is_alive())
        first.close()

    def test_config_rejects_unbounded_values(self):
        import yaml
        self.config['ssh']['max_connections'] = -1
        path = self.root / 'bad.yaml'
        path.write_text(yaml.safe_dump(self.config))
        with self.assertRaises(ValueError):
            load_config(path)


if __name__ == '__main__':
    unittest.main()
