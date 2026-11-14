"""Serialized SQLite + rotating JSONL telemetry; bounded, best-effort alerts."""
import json
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
import os
import queue
import re
import sqlite3
import threading
import time
from datetime import datetime, timezone
from urllib.request import Request, urlopen


class Webhook:
    def __init__(self, config):
        self.config = config
        self.url = os.environ.get(config.get('url_env', 'HONEYPOT_WEBHOOK_URL'), '')
        self.queue = queue.Queue(maxsize=config.get('queue_size', 32))
        self.stop = threading.Event()
        self.thread = None
        if config.get('enabled') and self.url:
            if not self.url.startswith('https://'):
                raise ValueError('Webhook URL must use HTTPS')
            self.thread = threading.Thread(target=self._run, name='webhook', daemon=True)
            self.thread.start()

    def submit(self, event):
        if self.thread and 'high_interest' in event['tags']:
            try:
                # Deliberately exclude attacker text, credentials and URLs from alerts.
                self.queue.put_nowait({'service': event['service'], 'kind': event['kind']})
            except queue.Full:
                pass

    def _run(self):
        next_send = 0
        while not self.stop.is_set():
            try:
                event = self.queue.get(timeout=0.2)
            except queue.Empty:
                continue
            if time.monotonic() < next_send:
                continue
            next_send = time.monotonic() + self.config.get('min_interval', 30)
            text = f"Honeypot high-interest event: {event['service']} / {event['kind']}"
            payload = ({'chat_id': self.config.get('chat_id'), 'text': text}
                       if self.config.get('format') == 'telegram' else
                       {'content': text, 'allowed_mentions': {'parse': []}})
            try:
                request = Request(self.url, data=json.dumps(payload).encode(),
                                  headers={'Content-Type': 'application/json'})
                with urlopen(request, timeout=3) as response:
                    response.read(1024)
            except Exception:
                logging.warning('Webhook delivery failed (details suppressed to protect tokens)')

    def close(self):
        self.stop.set()
        if self.thread:
            self.thread.join(timeout=4)


class Storage:
    def __init__(self, config, webhook=None):
        self.lock = threading.Lock()
        self.database = config['database']
        for path in (self.database, config['json_log']):
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.database, check_same_thread=False, timeout=5)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA busy_timeout=5000')
        self.db.executescript('''
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL,
                service TEXT NOT NULL, kind TEXT NOT NULL,
                source_ip TEXT NOT NULL, source_port INTEGER,
                username TEXT, password TEXT, path TEXT, user_agent TEXT,
                event_json TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS events_service ON events(service);
            CREATE INDEX IF NOT EXISTS events_source ON events(source_ip);
            CREATE INDEX IF NOT EXISTS events_username ON events(username);
            CREATE INDEX IF NOT EXISTS events_password ON events(password);
            CREATE INDEX IF NOT EXISTS events_path ON events(path);
            CREATE INDEX IF NOT EXISTS events_timestamp ON events(timestamp);
        ''')
        self.handler = RotatingFileHandler(config['json_log'],
            maxBytes=config.get('rotate_bytes', 10485760),
            backupCount=config.get('backup_count', 5), encoding='utf-8')
        self.handler.setFormatter(logging.Formatter('%(message)s'))
        self.webhook = Webhook(webhook or {})

    def record(self, service, kind, source_ip, source_port, **details):
        tags = [service, kind]
        payload = str(details.get('body', '')) + str(details.get('command', '')) + str(details.get('path', ''))
        if kind == 'command' or re.search(r'(?i)(union\s+select|/etc/passwd|\$\(|<script|\.\./)', payload):
            tags.append('high_interest')
        event = {'@timestamp': datetime.now(timezone.utc).isoformat(),
                 'ecs': {'version': '8.11.0'}, 'event': {'category': ['intrusion_detection'], 'type': ['info']},
                 'service': service, 'kind': kind, 'source': {'ip': source_ip, 'port': source_port},
                 'tags': tags, **details}
        encoded = json.dumps(event, ensure_ascii=True)
        with self.lock:
            self.db.execute('''INSERT INTO events
                (timestamp,service,kind,source_ip,source_port,username,password,path,user_agent,event_json)
                VALUES (?,?,?,?,?,?,?,?,?,?)''',
                (event['@timestamp'], service, kind, source_ip, source_port,
                 details.get('username'), details.get('password'), details.get('path'),
                 details.get('user_agent'), encoded))
            self.db.commit()
            self.handler.emit(logging.LogRecord('events', logging.INFO, '', 0, encoded, (), None))
        self.webhook.submit(event)

    def close(self):
        self.webhook.close()
        with self.lock:
            self.db.close()
            self.handler.close()
