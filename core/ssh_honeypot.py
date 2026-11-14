"""SSH authentication sink and strictly inert shell emulator."""
import os
from pathlib import Path
import socket
import socketserver
import threading
import time
import paramiko
from core.network import BoundedThreadingMixIn


def load_host_key(filename):
    path = Path(filename)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        key = paramiko.RSAKey.generate(3072)
        # Exclusive creation prevents accidental replacement of a persistent identity.
        try:
            with open(path, 'x', opener=lambda p, f: os.open(p, f, 0o600)) as output:
                key.write_private_key(output)
        except FileExistsError:
            pass
    return paramiko.RSAKey.from_private_key_file(str(path))


class SSHInterface(paramiko.ServerInterface):
    def __init__(self, server, transport, address):
        self.server, self.transport, self.address = server, transport, address
        self.shell_ready = threading.Event()
        self.username = ''

    def get_allowed_auths(self, username):
        return 'password'

    def check_auth_password(self, username, password):
        self.username = username
        self.server.storage.record('ssh', 'authentication', *self.address,
            username=username, password=password, client_banner=self.transport.remote_version)
        self.server.stopping.wait(self.server.config['tarpit_delay'])
        if self.server.stopping.is_set():
            return paramiko.AUTH_FAILED
        return paramiko.AUTH_SUCCESSFUL if self.server.config['fake_shell'] else paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        self.server.storage.record('ssh', 'authentication', *self.address, username=username,
            auth_method='publickey', public_key_fingerprint=key.get_fingerprint().hex(),
            client_banner=self.transport.remote_version)
        self.server.stopping.wait(self.server.config['tarpit_delay'])
        return paramiko.AUTH_FAILED

    def check_auth_none(self, username):
        self.server.storage.record('ssh', 'authentication', *self.address, username=username,
            auth_method='none', client_banner=self.transport.remote_version)
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == 'session' else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        self.shell_ready.set()
        return True

    def check_channel_exec_request(self, channel, command):
        self.server.storage.record('ssh', 'command', *self.address, username=self.username,
                                   command=command[:4096].decode('utf-8', 'replace'), mode='exec_rejected')
        return False


def fake_shell(channel, interface, deadline):
    """Only fixed strings are returned. No filesystem, interpreter or process access."""
    channel.settimeout(0.5)
    channel.sendall(b'Welcome to Ubuntu 22.04.4 LTS\r\nubuntu@prod-db-01:~$ ')
    line = bytearray()
    while time.monotonic() < deadline and not interface.server.stopping.is_set():
        try:
            data = channel.recv(1024)
        except socket.timeout:
            continue
        if not data:
            return
        for char in data:
            if char in (10, 13):
                if char == 10 and not line:
                    continue
                command = line.decode('utf-8', 'replace')
                line.clear()
                interface.server.storage.record('ssh', 'command', *interface.address,
                    username=interface.username, command=command, mode='fake_shell')
                if command.strip() in ('exit', 'logout'):
                    channel.sendall(b'\r\nlogout\r\n')
                    return
                responses = {'whoami': 'ubuntu', 'pwd': '/home/ubuntu',
                             'id': 'uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu)', 'ls': ''}
                answer = responses.get(command.strip(), 'bash: command not found')
                channel.sendall(('\r\n' + answer + '\r\nubuntu@prod-db-01:~$ ').encode())
            elif char in (8, 127):
                if line:
                    line.pop()
            elif 32 <= char <= 126 or char >= 128:
                if len(line) >= 4096:
                    interface.server.storage.record('ssh', 'command', *interface.address,
                        username=interface.username, command=line.decode('utf-8', 'replace'), truncated=True)
                    return
                line.append(char)
                channel.sendall(bytes([char]))


class SSHHandler(socketserver.BaseRequestHandler):
    def handle(self):
        transport = paramiko.Transport(self.request)
        transport.local_version = self.server.config['banner']
        timeout = self.server.config['session_timeout']
        transport.banner_timeout = min(timeout, 10)
        transport.auth_timeout = timeout
        transport.add_server_key(self.server.host_key)
        interface = SSHInterface(self.server, transport, self.client_address)
        deadline = time.monotonic() + timeout
        try:
            negotiated = threading.Event()
            transport.start_server(event=negotiated, server=interface)
            while time.monotonic() < deadline and not self.server.stopping.is_set():
                channel = transport.accept(timeout=0.2)
                if channel:
                    try:
                        while not interface.shell_ready.wait(0.1):
                            if channel.closed or time.monotonic() >= deadline or self.server.stopping.is_set():
                                return
                        fake_shell(channel, interface, deadline)
                    finally:
                        channel.close()
                    return
                if not transport.is_active():
                    return
        except (EOFError, OSError, paramiko.SSHException):
            pass
        finally:
            transport.close()


class SSHHoneypot(BoundedThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    request_queue_size = 64

    def __init__(self, config, storage):
        self.config, self.storage = config, storage
        self.host_key = load_host_key(config['host_key'])
        self.setup_limits(config['max_connections'])
        super().__init__((config['host'], config['port']), SSHHandler)
