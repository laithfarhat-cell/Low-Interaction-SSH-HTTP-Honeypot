"""Configuration, concurrent listeners, and cooperative shutdown."""
import argparse
import logging
import math
import os
import signal
import threading
from pathlib import Path
import yaml
from core.storage import Storage
from core.ssh_honeypot import SSHHoneypot
from core.http_honeypot import HTTPHoneypot


def load_config(filename):
    with open(filename, encoding='utf-8') as source:
        config = yaml.safe_load(source)
    if not isinstance(config, dict):
        raise ValueError('Configuration must be a mapping')
    for service in ('ssh', 'http'):
        section = config[service]
        for field, low, high in [('port', 1, 65535), ('max_connections', 1, 1024)]:
            value = section[field]
            if type(value) is not int or not low <= value <= high:
                raise ValueError(f'{service}.{field} must be between {low} and {high}')
        if type(section['enabled']) is not bool:
            raise ValueError(f'{service}.enabled must be boolean')
    for service, field, low, high in [('ssh', 'tarpit_delay', 0, 30),
            ('ssh', 'session_timeout', 1, 3600), ('http', 'timeout', 1, 120),
            ('http', 'max_body_bytes', 0, 1048576)]:
        value = config[service][field]
        if type(value) not in (int, float) or not math.isfinite(value) or not low <= value <= high:
            raise ValueError(f'Invalid {service}.{field}')
    if type(config['http']['max_body_bytes']) is not int:
        raise ValueError('http.max_body_bytes must be an integer')
    if type(config['ssh']['fake_shell']) is not bool:
        raise ValueError('ssh.fake_shell must be boolean')
    banner = config['ssh']['banner']
    if not isinstance(banner, str) or not banner.startswith('SSH-2.0-') or len(banner) > 253 or any(ord(c) < 32 or ord(c) > 126 for c in banner):
        raise ValueError('Invalid SSH banner')
    for field, low, high in [('rotate_bytes', 1024, 1073741824), ('backup_count', 1, 100)]:
        value = config['storage'][field]
        if type(value) is not int or not low <= value <= high:
            raise ValueError(f'Invalid storage.{field}')
    webhook = config.get('webhook', {})
    for field, default, low, high in [('queue_size', 32, 1, 1024), ('min_interval', 30, 1, 86400)]:
        value = webhook.get(field, default)
        if type(value) is not int or not low <= value <= high:
            raise ValueError(f'Invalid webhook.{field}')
    if webhook.get('format', 'discord') not in ('discord', 'telegram'):
        raise ValueError('Invalid webhook format')
    return config


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description='Isolated SSH and HTTP deception service')
    parser.add_argument('--config', default='config.yaml')
    parser.add_argument('--dashboard', action='store_true', help='Read-only dashboard (no listeners)')
    parser.add_argument('--check-config', action='store_true')
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    logging.getLogger('paramiko').setLevel(logging.CRITICAL)
    config = load_config(args.config)
    if args.check_config:
        print('Configuration valid')
        return
    if args.dashboard:
        from cli.dashboard import run_dashboard
        try:
            run_dashboard(config['storage']['database'])
        except KeyboardInterrupt:
            pass
        return
    stopped = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stopped.set())
    storage = Storage(config['storage'], config.get('webhook'))
    servers, threads = [], []
    try:
        for name, cls in [('ssh', SSHHoneypot), ('http', HTTPHoneypot)]:
            if config[name]['enabled']:
                server = cls(config[name], storage)
                servers.append(server)
                def serve(listener=server):
                    try:
                        listener.serve_forever(poll_interval=0.2)
                    finally:
                        stopped.set()
                thread = threading.Thread(target=serve, name=name)
                thread.start()
                threads.append(thread)
                logging.info('%s listener ready on port %s', name, config[name]['port'])
        if not servers:
            raise ValueError('At least one service must be enabled')
        stopped.wait()
    finally:
        for server in servers:
            server.stop()
        for thread in threads:
            thread.join()
        storage.close()


if __name__ == '__main__':
    main()
