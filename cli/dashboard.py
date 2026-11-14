"""Read-only live telemetry, safe from Rich markup and terminal escape injection."""
from pathlib import Path
import re
import sqlite3
import time
from rich.console import Group
from rich.live import Live
from rich.table import Table
from rich.text import Text


def safe(value):
    return Text(re.sub(r'[\x00-\x1f\x7f-\x9f]', '?', str(value))[:160])


def table(title, headings, rows):
    result = Table(title=title, expand=True)
    for heading in headings:
        result.add_column(heading)
    for row in rows:
        result.add_row(*(safe(value) for value in row))
    return result


def snapshot(db):
    counts = list(db.execute('SELECT service, count(*) FROM events GROUP BY service'))
    counts.append(('TOTAL', sum(row[1] for row in counts)))
    panels = [table('Captured events (not unique attackers)', ['Service', 'Count'], counts)]
    for title, column, where in [
        ('Top source IPs', 'source_ip', '1=1'),
        ('Top usernames', 'username', "username IS NOT NULL"),
        ('Top passwords', 'password', "password IS NOT NULL"),
        ('Probed endpoints', 'path', "service='http'"),
        ('User-Agents', 'user_agent', "service='http'")]:
        panels.append(table(title, ['Value', 'Count'], db.execute(
            f'SELECT {column}, count(*) AS n FROM events WHERE {where} GROUP BY {column} ORDER BY n DESC LIMIT 10')))
    panels.append(table('Latest 10 events', ['UTC', 'Service', 'Kind', 'Source', 'Username / path'], db.execute(
        "SELECT timestamp,service,kind,source_ip,coalesce(username,path,'') FROM events ORDER BY id DESC LIMIT 10")))
    return Group(*panels)


def run_dashboard(database, refresh=2):
    uri = Path(database).resolve().as_uri() + '?mode=ro'
    with sqlite3.connect(uri, uri=True, timeout=5) as db:
        with Live(snapshot(db), refresh_per_second=1, screen=True) as live:
            while True:
                live.update(snapshot(db))
                time.sleep(refresh)
