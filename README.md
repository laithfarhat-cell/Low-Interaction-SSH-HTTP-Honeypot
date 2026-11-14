# Low-Interaction SSH & HTTP Honeypot

A bounded, multithreaded Python deception service for collecting automated SSH
brute-force attempts and HTTP probes. It exposes static decoys, not intentionally
vulnerable software. The optional shell is an inert string emulator.

```text
 Untrusted scanners / bots
          |
     firewall / isolated DMZ         Operator terminal
          |                               |
   +------+-------------------+     rich --dashboard
   | non-root container       |           |
   | SSH :2222    HTTP :8080   |           | read-only SQLite
   | Paramiko     static      |           |
   | auth sink    decoys      |           |
   +------+----------+--------+           |
          +-----+----+                    |
                v                         |
      serialized Storage ----------------+
          |            |
     SQLite WAL   rotating JSONL --> SIEM shipper
          |
     bounded alert queue --> optional HTTPS webhook

 persistent mounts: ./data (sensitive telemetry), ./keys (SSH identity)
```

## Security boundary — read before deploying

**Deploy only on infrastructure you own or have permission to monitor.** Put the
service in a dedicated VM/DMZ with no route to production systems, metadata APIs,
secrets, or internal management networks. Containerization is defense in depth,
not a security boundary against kernel or dependency vulnerabilities. Never mount
the Docker socket, host root filesystem, or real application credentials.

* No attacker input is passed to an OS process, Python interpreter, or template
  engine. There are no `os.system`, `subprocess`, or `eval` calls in the service.
* Shell authentication is **rejected by default**. With `fake_shell: true`, any
  password succeeds after the tarpit, but only a single session with fixed
  responses is offered. `whoami`, `pwd`, `id`, `ls`, and `exit` are simulated.
  Exec commands are recorded and rejected; SFTP, agent/X11/TCP forwarding,
  remote file access and subsystem requests are not implemented.
* The shell prompt always identifies the fictional `ubuntu@prod-db-01`, regardless
  of supplied username. Fake secrets in HTTP responses have no real privilege.
* Do not use this host key for any legitimate SSH service. `AutoAddPolicy` in the
  tests is for the local test honeypot only, not production SSH clients.
* Log records contain raw passwords, headers, cookies and bodies. Restrict access,
  encrypt disks/backups, set a retention policy, and comply with privacy laws.
  Do not open raw attacker text directly in a terminal; the dashboard strips
  control characters and uses Rich `Text` rather than markup interpolation.
* Restrict egress by external firewall: none is needed unless webhooks are enabled.
  Restrict webhook egress to your approved destination. Webhook URL configuration
  is trusted operator input. Incoming headers cannot change its destination.
* Source IP means the direct socket peer. Untrusted `X-Forwarded-For` headers are
  recorded but never trusted. Do not put an authentication proxy in front of SSH.

## Quick start (Python 3.11+)

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python main.py --check-config
python main.py
# In another terminal, with the same virtual environment:
python main.py --dashboard
# Ctrl-C or SIGTERM cleanly stops listeners and closes telemetry.
```

Paths in configuration are relative to the working directory. Run from this
repository, or use absolute paths. `--config /path/to/config.yaml` selects a
configuration. The dashboard is a separate, read-only process; start collection
first. It never binds listening ports. Run it only in a trusted operator terminal,
not a publicly exposed web terminal.

## Docker Compose

The image runs as **honeypot_user (UID/GID 10001)** with no privileged ports or
Linux capabilities. Prepare host bind mounts before the first launch (Linux):

```bash
mkdir -p data keys
sudo chown 10001:10001 data keys
sudo chmod 700 data keys
docker compose up --build -d
docker compose logs -f
# Interactive, read-only SQLite analytics:
docker compose exec honeypot python main.py --dashboard
docker compose down
```

The container uses a read-only root filesystem, a small noexec temporary mount,
no-new-privileges, PID/CPU/memory limits and bounded Docker logs. Persistent mounts
retain the host key and data across rebuilds. On SELinux hosts configure the
appropriate bind-mount labels. Docker is not required for local use.

By default Compose publishes ports on **all host interfaces**. Limit host firewall
rules before starting. To attract standard-port traffic, map host `22:2222` and
`80:8080` only on a dedicated IP/host; never replace your own management SSH
listener or expose management services alongside the honeypot.

## Configuration

`config.yaml` contains all defaults:

| Setting | Default | Purpose |
|---|---|---|
| `ssh.port` / `http.port` | 2222 / 8080 | Unprivileged listeners |
| `ssh.banner` | OpenSSH Ubuntu string | SSH identification banner |
| `ssh.tarpit_delay` | 1.5 seconds | Password/public-key rejection delay |
| `ssh.fake_shell` | false | Opt in to inert interactive sessions |
| `ssh.session_timeout` | 60 seconds | Absolute SSH connection lifetime |
| `ssh.host_key` | keys/ssh_host_rsa_key | Persistent 3072-bit RSA private key |
| `*.max_connections` | 64 per protocol | Reject excess sockets without spawning workers |
| `http.timeout` | 10 seconds | Socket inactivity timeout |
| `http.max_body_bytes` | 65536 | Reject oversized bodies with 413 |
| `storage.rotate_bytes` | 10485760 | JSONL file rotation size |
| `storage.backup_count` | 5 | Rotated JSON files retained |
| `webhook.enabled` | false | Optional best-effort notifications |

Authentication `none` probes and public-key offers are logged (no password exists
for those methods). Password attempts include username, password, peer IP/port and
client banner. Unsupported authentication mechanisms are not advertised.

HTTP captures all parsed methods, raw request target, repeated query values,
User-Agent, ordered header pairs (including duplicates), UTF-8 replacement-decoded
body and exact body bytes in base64. No compressed-body decompression or multipart
parsing occurs. Bodies above the cap are rejected without reading or storing a
prefix. Chunked transfer encoding is rejected with 501, conflicting Content-Length
headers with 400, and connections close after each request. Malformed requests
rejected by Python's HTTP parser before dispatch are not stored. HTTP header and
request-line limits are inherited from `http.server`; this is a decoy, not a full
HTTP reverse proxy. Use external connection/rate limits against slow-drip clients
(the HTTP timeout is inactivity-based, not an absolute deadline).

### Webhooks

Only command events and simple suspicious payload signatures (`union select`,
`/etc/passwd`, `$(`, `<script`, `../`) are tagged `high_interest`. Signatures are
heuristics, not a detection engine. Alerts omit credentials and attacker text,
disable Discord mentions, use a bounded queue, a three-second network timeout and
one global rate limiter. Excess alerts are discarded; webhook failures never
block capture and are not retried.

For Discord, set `webhook.enabled: true`, `format: discord` and pass
`HONEYPOT_WEBHOOK_URL` into the process environment. For Telegram, set
`format: telegram`, `chat_id`, and set that variable to
`https://api.telegram.org/bot<TOKEN>/sendMessage`. For Compose, explicitly add
`environment: [HONEYPOT_WEBHOOK_URL]` to the service and export the variable on the
host. Never commit tokens to configuration or bake them into images.

## Telemetry and analytics

`data/honeypot.db` uses SQLite WAL, a shared connection protected by a lock, and
indexes on service, IP, username, password, endpoint and timestamp. Each event is
committed before the corresponding JSON line is emitted. This is **not an atomic
transaction across both sinks**: a crash/disk failure can leave them out of sync.
SQLite is the query source of truth. Monitor disk space and service errors.

`data/honeypot_events.json` is newline-delimited JSON, despite its `.json` extension.
It uses ECS-inspired timestamp/source/event fields plus application-specific
`service` and `kind` fields (not a fully ECS-conformant schema). Configure your SIEM
shipper's JSONL parser and schema mapping. Example password event:

```json
{"@timestamp":"2026-11-14T12:00:00+00:00","ecs":{"version":"8.11.0"},"event":{"category":["intrusion_detection"],"type":["info"]},"service":"ssh","kind":"authentication","source":{"ip":"192.0.2.42","port":43122},"tags":["ssh","authentication"],"username":"root","password":"admin123","client_banner":"SSH-2.0-example"}
```

Example HTTP fields (common envelope omitted):

```json
{"service":"http","kind":"request","method":"POST","uri":"/login?a=1","path":"/login","query":{"a":["1"]},"user_agent":"scanner","headers":[["Host","decoy"]],"body":"username=admin","body_base64":"dXNlcm5hbWU9YWRtaW4=","response_status":200,"body_rejected":false}
```

The dashboard shows per-service event counts, top ten peer IPs, usernames,
passwords, endpoints, User-Agents and the latest ten events. Counts represent
**events**, not unique sessions or proven malicious actors; shell commands also
contribute to SSH totals. Live refresh defaults to two seconds.

SQLite does not auto-expire records. Schedule retention during maintenance, back
up using SQLite's online backup API, and avoid copying a live `.db` without its
WAL. Very large datasets require archival/retention: dashboard aggregations may
be expensive. JSONL rotates independently; configure the shipper to track rotated
files and restrict its read permissions. Newly generated keys use mode 0600;
`main.py` applies umask 0077 to new telemetry. Existing file permissions remain
the operator's responsibility. Run only one collector per database/key pair.

## Development and verification

```bash
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m compileall -q core cli main.py
```

Tests use loopback ephemeral ports and temporary directories: concurrent storage,
JSON round trips, HTTP decoys/payload caps, persistent host keys, SSH rejection,
fake-shell non-execution, idle-client shutdown, and config validation. No external
webhook is contacted. Dependency ranges permit security updates; resolve and pin
an audited lockfile/image digest in your deployment pipeline. Load-test your
chosen limits before Internet exposure. This project is a deployment baseline,
not a claim of independent security audit or immunity to denial of service.
