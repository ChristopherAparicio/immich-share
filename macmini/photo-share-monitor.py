#!/usr/bin/env python3
"""photo-share-monitor — console and telemetry for immich-share.

- Serves a console to create, list, and close shares and view album statistics.
- Continuously ingests the Caddy access log over the tunnel into local SQLite,
  retaining opens, downloads, and unique visitors after a share expires.
  Client addresses are hashed for privacy.
- Exposes /devhub for dashboards and infrastructure alerts.
Actions call the immich-share CLI without shell=True. Tailnet only.
"""

import base64
import configparser
import hashlib
import hmac
import ipaddress
import json
import os
import re
import sqlite3
import stat
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

PORT = 9097
CONFIG = Path.home() / ".config/immich-share/config.ini"
CLI = str(Path(__file__).resolve().parents[1] / "immich-share")
DATA_DIR = Path.home() / "photo-share-monitor"
DATA_DIR.mkdir(exist_ok=True, mode=0o700)
DATA_DIR.chmod(0o700)
DB = DATA_DIR / "telemetry.db"
TTL_RE = re.compile(r"^\d+[hdj]$")
KEY_RE = re.compile(r"^[A-Za-z0-9_-]{8,128}$")
INGEST_EVERY = 45


def _read_private_secret(path, label):
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise RuntimeError(f"{label} file cannot be opened securely: {path} ({exc})")
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_mode & 0o077
            or info.st_uid != os.geteuid()
        ):
            raise RuntimeError(
                f"{label} file must be regular, owned by the current user, and private: {path}"
            )
        with os.fdopen(fd) as handle:
            fd = -1
            value = handle.read(16_385)
    finally:
        if fd >= 0:
            os.close(fd)
    if not value.strip() or len(value) > 16_384 or "\x00" in value:
        raise RuntimeError(f"{label} file is empty or invalid: {path}")
    return value.strip()


_cfg = configparser.ConfigParser()
_cfg.read(CONFIG)
IMMICH = _cfg["immich"]["url"].rstrip("/")
_immich_url = urlsplit(IMMICH)
if _immich_url.scheme not in {"http", "https"} or not _immich_url.hostname:
    raise RuntimeError("[immich] url must be an absolute HTTP(S) URL")
try:
    _immich_loopback = ipaddress.ip_address(_immich_url.hostname).is_loopback
except ValueError:
    _immich_loopback = _immich_url.hostname.lower() == "localhost"
if (
    _immich_url.scheme == "http"
    and not _immich_loopback
    and not _cfg.getboolean("immich", "allow_http_over_private_tunnel", fallback=False)
):
    raise RuntimeError(
        "refusing to send the Immich API key over clear-text HTTP without an encrypted private-tunnel acknowledgement"
    )
API_KEY = _read_private_secret(
    Path(_cfg["immich"]["api_key_file"]).expanduser(), "Immich API key"
)
VPS_SSH = _cfg["vps"]["ssh"]
if not re.fullmatch(
    r"(?:[A-Za-z0-9_.-]+@)?(?:[A-Za-z0-9_.-]+|\[[0-9A-Fa-f:]+\])", VPS_SSH
):
    raise RuntimeError("invalid [vps] ssh target; use an SSH alias or user@host")
# Tailnet-only bind. The safe default is 127.0.0.1; use the tailnet address to
# access the console from another device. Never use 0.0.0.0 in production.
BIND = os.environ.get("PHOTO_SHARE_BIND") or _cfg.get(
    "monitor", "bind", fallback="127.0.0.1"
)
if BIND in {"0.0.0.0", "::", "*"}:
    raise RuntimeError("wildcard monitor binds are forbidden")
# DNS rebinding defense: accept only these Host values. A browser cannot forge
# Host, so a malicious page rebound to localhost or the tailnet address is
# rejected. Add a tailnet hostname to [monitor] allowed_hosts when needed.
_extra_hosts = {
    h.strip().lower()
    for h in _cfg.get("monitor", "allowed_hosts", fallback="").split(",")
    if h.strip()
}
ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1", BIND.lower()} | _extra_hosts
MONITOR_USER = _cfg.get("monitor", "username", fallback="immich-share")
_password_path = _cfg.get("monitor", "password_file", fallback="").strip()
MONITOR_PASSWORD = ""
if _password_path:
    password_file = Path(_password_path).expanduser()
    MONITOR_PASSWORD = _read_private_secret(password_file, "monitor password")
    if len(MONITOR_PASSWORD) < 16:
        raise RuntimeError("monitor password must contain at least 16 characters")
try:
    _bind_is_loopback = ipaddress.ip_address(BIND).is_loopback
except ValueError:
    _bind_is_loopback = BIND.lower() == "localhost"
if not MONITOR_PASSWORD:
    raise RuntimeError(
        "the monitor requires [monitor] password_file, including on loopback"
    )
if not _bind_is_loopback and not _cfg.getboolean(
    "monitor", "allow_http_over_private_tunnel", fallback=False
):
    raise RuntimeError(
        "a non-loopback monitor bind requires explicit confirmation of an encrypted private tunnel"
    )
RETENTION_DAYS = _cfg.getint("monitor", "telemetry_retention_days", fallback=90)
if not 1 <= RETENTION_DAYS <= 3650:
    raise RuntimeError("telemetry_retention_days must be between 1 and 3650")

# Salt for client-address hashing, generated once and never shared.
_salt_f = DATA_DIR / "ip.salt"
if not _salt_f.exists():
    import secrets

    _salt_f.write_text(secrets.token_hex(16))
    _salt_f.chmod(0o600)
SALT = _salt_f.read_text().strip()

_dblock = threading.Lock()
_auth_lock = threading.Lock()
_auth_failures = {}


def _db():
    c = sqlite3.connect(DB, timeout=10)
    c.row_factory = sqlite3.Row
    return c


def _init_db():
    with _dblock, _db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS shares(
            key TEXT PRIMARY KEY, album TEXT, for_label TEXT,
            first_seen REAL, last_seen REAL);
        CREATE TABLE IF NOT EXISTS events(
            ts REAL, key TEXT, ip_hash TEXT, action TEXT, status INTEGER);
        CREATE INDEX IF NOT EXISTS ix_events_key ON events(key);
        CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts);
        CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
        """)
    DB.chmod(0o600)


def _purge_old_events():
    cutoff = time.time() - RETENTION_DAYS * 86400
    with _dblock, _db() as c:
        c.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
        c.execute("DELETE FROM shares WHERE last_seen < ?", (cutoff,))


def _meta_get(k, default=None):
    with _dblock, _db() as c:
        r = c.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
        return r["v"] if r else default


def _meta_set(k, v):
    with _dblock, _db() as c:
        c.execute(
            "INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=?",
            (k, str(v), str(v)),
        )


def _iphash(ip):
    return hashlib.sha256(f"{SALT}:{ip}".encode()).hexdigest()[:16]


def _immich_shares():
    req = Request(f"{IMMICH}/api/shared-links", headers={"x-api-key": API_KEY})
    with urlopen(req, timeout=8) as r:
        links = json.load(r)
    out, now = [], datetime.now(timezone.utc)
    for link in links:
        exp = link.get("expiresAt")
        expd = datetime.fromisoformat(exp.replace("Z", "+00:00")) if exp else None
        if expd and expd < now:
            continue
        out.append(
            {
                "key": link.get("key", ""),
                "for": link.get("description") or "",
                "album": (link.get("album") or {}).get("albumName", ""),
                "expires_in": _human_delta(expd - now) if expd else "∞",
            }
        )
    return out


def _albums():
    req = Request(f"{IMMICH}/api/albums", headers={"x-api-key": API_KEY})
    with urlopen(req, timeout=8) as r:
        al = json.load(r)
    return sorted((a["albumName"], a.get("assetCount", 0)) for a in al)


def _human_delta(td):
    s = int(td.total_seconds())
    if s < 3600:
        return f"{s // 60} min"
    if s < 86400:
        return f"{s // 3600} h"
    return f"{s // 86400} d"


# Actual IPP routes observed on 2026-08-25: the size segment conveys intent.
_SIZE_ACTION = {"thumbnail": "thumb", "preview": "view", "original": "download"}


def _classify(method, uri):
    """Return (key, action): thumbnail=navigation, preview=view, original=download."""
    u = uri.split("?")[0]
    m = re.match(
        r"^/share/(?:photo|video)/([A-Za-z0-9_-]{8,})/[0-9a-fA-F-]+/(thumbnail|preview|original)$",
        u,
    )
    if m:
        return m.group(1), _SIZE_ACTION[m.group(2)]
    m = re.match(r"^/(?:share|s)/([A-Za-z0-9_-]{8,})/?$", u)
    if m:
        return m.group(1), "gallery"
    return None, None


# ─── Caddy log ingestion into SQLite ──────────────────────────────


def _vps_fetch():
    """Use one SSH call to retrieve WireGuard handshakes and the Caddy log tail."""
    p = subprocess.run(
        [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "ForwardAgent=no",
            "-o",
            "ConnectTimeout=6",
            VPS_SSH,
            "sudo -n wg show wg0 latest-handshakes; echo '==='; "
            "docker exec caddy tail -n 8000 /data/access.log 2>/dev/null",
        ],
        capture_output=True,
        text=True,
        timeout=20,
    )
    wg, _, log = p.stdout.partition("===\n")
    return wg, log


def _ingest_once():
    try:
        wg, log = _vps_fetch()
    except Exception:
        return
    now = time.time()
    peers = sum(
        1
        for ln in wg.strip().splitlines()
        if ln.split("\t")[-1].isdigit() and now - int(ln.split("\t")[-1]) < 300
    )
    _meta_set("peers_up", peers)
    _meta_set("last_ingest", int(now))

    last_ts = float(_meta_get("last_event_ts", 0) or 0)
    shares = {s["key"]: s for s in (_immich_shares() or [])}
    rows, maxts = [], last_ts
    for line in log.splitlines():
        try:
            e = json.loads(line)
        except ValueError:
            continue
        ts = e.get("ts", 0)
        if ts <= last_ts:
            continue
        maxts = max(maxts, ts)
        req = e.get("request", {})
        status = e.get("status")
        ip = _iphash(req.get("client_ip") or req.get("remote_ip") or "?")
        if status == 429:  # Rate limited; possible password brute force.
            rows.append((ts, "", ip, "ratelimit", 429))
            continue
        key, action = _classify(req.get("method", ""), req.get("uri", ""))
        if not key or status not in (200, 206):
            continue
        rows.append((ts, key, ip, action, status))
    if rows:
        with _dblock, _db() as c:
            c.executemany(
                "INSERT INTO events(ts,key,ip_hash,action,status) VALUES(?,?,?,?,?)",
                rows,
            )
            for k, s in shares.items():
                c.execute(
                    """INSERT INTO shares(key,album,for_label,first_seen,last_seen)
                             VALUES(?,?,?,?,?) ON CONFLICT(key) DO UPDATE SET
                             album=excluded.album, for_label=excluded.for_label, last_seen=excluded.last_seen""",
                    (k, s["album"], s["for"], now, now),
                )
        _meta_set("last_event_ts", maxts)


def _ingest_loop():
    _init_db()
    while True:
        try:
            _ingest_once()
            last_purge = float(_meta_get("last_purge", 0) or 0)
            if time.time() - last_purge > 86400:
                _purge_old_events()
                _meta_set("last_purge", int(time.time()))
        except Exception:
            pass
        time.sleep(INGEST_EVERY)


# ─── Statistics queries ───────────────────────────────────────────


def _share_stats(key):
    with _dblock, _db() as c:
        r = c.execute(
            """SELECT
            SUM(action='gallery') opens, SUM(action='view') views,
            SUM(action='download') downloads, COUNT(DISTINCT ip_hash) visitors
            FROM events WHERE key=?""",
            (key,),
        ).fetchone()
    return {
        "opens": r["opens"] or 0,
        "views": r["views"] or 0,
        "downloads": r["downloads"] or 0,
        "visitors": r["visitors"] or 0,
    }


def _album_stats():
    with _dblock, _db() as c:
        rows = c.execute("""SELECT s.album album,
            COUNT(DISTINCT s.key) shares,
            SUM(e.action='gallery') opens,
            SUM(e.action='view') views,
            SUM(e.action='download') downloads,
            COUNT(DISTINCT e.ip_hash) visitors
            FROM shares s LEFT JOIN events e ON e.key=s.key
            GROUP BY s.album HAVING opens>0 OR downloads>0
            ORDER BY downloads DESC, opens DESC""").fetchall()
    return [
        {
            "album": r["album"],
            "shares": r["shares"],
            "opens": r["opens"] or 0,
            "views": r["views"] or 0,
            "downloads": r["downloads"] or 0,
            "visitors": r["visitors"] or 0,
        }
        for r in rows
    ]


def _tunnel():
    p = _meta_get("peers_up")
    return "?" if p is None else f"{p}/2"


def _authfail_15m():
    cutoff = time.time() - 900
    with _dblock, _db() as c:
        r = c.execute(
            "SELECT COUNT(*) n FROM events WHERE action='ratelimit' AND ts>?", (cutoff,)
        ).fetchone()
    return r["n"] or 0


# ─── HTTP ─────────────────────────────────────────────────────────

PAGE = r"""<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1"><title>Photo Share</title><style>
:root{--bg:#0d0e12;--card:#16181f;--card2:#1c1f28;--bd:#282c37;--tx:#e8eaef;--dim:#868c9c;--acc:#5b9cff;--ok:#3ddc84;--warn:#ffcc55;--danger:#ff6b6b}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--tx);font:14px/1.55 -apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif}
.wrap{max-width:900px;margin:0 auto;padding:28px 18px 80px}
.top{display:flex;align-items:baseline;gap:12px;margin-bottom:22px}
h1{font-size:19px;font-weight:650;margin:0}.sub{color:var(--dim);font-size:12.5px}
.pill{margin-left:auto;display:flex;gap:8px;align-items:center;font-size:12px;color:var(--dim);font-family:ui-monospace,monospace}
.dot{width:7px;height:7px;border-radius:50%;display:inline-block;background:var(--ok)}.dot.warn{background:var(--warn)}
.card{background:var(--card);border:1px solid var(--bd);border-radius:14px;padding:20px;margin-bottom:18px}
.card h2{font-size:13px;font-weight:600;margin:0 0 14px;letter-spacing:.01em}
.grid{display:grid;grid-template-columns:2fr 1fr 1fr auto;gap:12px;align-items:end}
@media(max-width:640px){.grid{grid-template-columns:1fr}}
label{display:block;font-size:10.5px;color:var(--dim);text-transform:uppercase;letter-spacing:.05em;margin-bottom:5px}
select,input{width:100%;background:var(--bg);border:1px solid var(--bd);color:var(--tx);padding:10px 12px;border-radius:9px;font-size:14px;font-family:inherit;outline:none}
select:focus,input:focus{border-color:var(--acc)}
button{border:0;border-radius:9px;font-size:13px;font-weight:600;cursor:pointer;font-family:inherit;transition:.12s}
.primary{background:var(--acc);color:#fff;padding:10px 18px;white-space:nowrap}.primary:hover{filter:brightness(1.08)}.primary:disabled{opacity:.5;cursor:default}
.copy{background:var(--card2);color:var(--tx);border:1px solid var(--bd);padding:5px 11px;font-size:11px}.copy:hover{border-color:var(--acc)}
.close{background:transparent;border:1px solid var(--bd);color:var(--danger);padding:5px 12px;font-size:12px}.close:hover{border-color:var(--danger)}
.result{background:linear-gradient(180deg,#12241a,#12201a);border:1px solid #235c3c;border-radius:11px;padding:16px;margin-top:16px;display:none}
.result.show{display:block;animation:f .25s}@keyframes f{from{opacity:0;transform:translateY(-4px)}}
.rrow{display:flex;align-items:center;gap:10px;margin:7px 0;font-family:ui-monospace,monospace;font-size:12.5px}
.rrow b{color:var(--dim);font-weight:400;min-width:92px;font-family:inherit;font-size:12px}
.rrow span.v{flex:1;word-break:break-all;color:var(--tx)}
.hint{color:var(--dim);font-size:11.5px;margin-top:10px}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;font-size:10.5px;text-transform:uppercase;letter-spacing:.05em;color:var(--dim);font-weight:600;padding:0 10px 9px;border-bottom:1px solid var(--bd)}
th.n,td.n{text-align:right;font-variant-numeric:tabular-nums;font-family:ui-monospace,monospace}
td{padding:11px 10px;border-bottom:1px solid var(--bd);vertical-align:middle}
tr:last-child td{border-bottom:0}
.nm{font-weight:600}.mut{color:var(--dim);font-size:12px}
.tag{display:inline-block;background:var(--card2);border:1px solid var(--bd);border-radius:6px;padding:1px 7px;font-size:11px;color:var(--dim);font-family:ui-monospace,monospace}
.empty{color:var(--dim);font-size:13px;padding:10px 2px}
.big{font-variant-numeric:tabular-nums;font-weight:650}
.toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%);background:var(--card2);border:1px solid var(--bd);padding:11px 18px;border-radius:10px;opacity:0;transition:.2s;font-size:13px;pointer-events:none}
.toast.show{opacity:1}
</style></head><body><div class=wrap>
<div class=top><h1>📸 Photo Share</h1><div class=sub>Immich shares · closed by default</div>
<div class=pill id=pill><span class=dot></span><span id=pilltxt>…</span></div></div>

<div class=card><h2>New share</h2>
<div class=grid>
<div><label>Album</label><select id=album></select></div>
<div><label>Duration</label><input id=ttl value=48h placeholder=48h></div>
<div><label>For (optional)</label><input id=for placeholder=Alex></div>
<div><button class=primary id=create>Create</button></div></div>
<div class=result id=result>
<div class=rrow><b>Link</b><span class=v id=rlink></span><button class=copy data-c=rlink>copy</button></div>
<div class=rrow><b>Password</b><span class=v id=rpw></span><button class=copy data-c=rpw>copy</button></div>
<div class=hint>📤 Send the link and password over <b>two different channels</b> (for example, the link by WhatsApp and password by SMS).</div>
</div></div>

<div class=card><h2>Active shares</h2>
<div id=shares><div class=empty>loading…</div></div></div>

<div class=card><h2>Album statistics</h2>
<div id=stats><div class=empty>loading…</div></div>
<div class=hint>Unique visitors are derived from hashed client addresses. History remains available after a share expires.</div></div>
</div><div class=toast id=toast></div>
<script>
const $=s=>document.querySelector(s),esc=s=>(s||'').replace(/[<>&"]/g,c=>({'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;'}[c]));
function toast(m){const t=$('#toast');t.textContent=m;t.classList.add('show');clearTimeout(t._);t._=setTimeout(()=>t.classList.remove('show'),1900)}
async function j(u,o){const r=await fetch(u,o);return r.json()}
async function loadAlbums(){const a=await j('/albums');$('#album').innerHTML=a.map(x=>`<option value="${esc(x[0])}">${esc(x[0])} · ${x[1]}</option>`).join('')}
function pill(d){const w=(d.peers<2)||(d.auth_fail>0);$('#pill').firstElementChild.className='dot'+(w?' warn':'');
 $('#pilltxt').textContent=`tunnel ${d.tunnel} · ${d.auth_fail} password failures/15 min`}
async function loadShares(){const d=await j('/shares');pill(d);
 if(!d.shares.length){$('#shares').innerHTML='<div class=empty>No active shares — no public attack surface.</div>';return}
 $('#shares').innerHTML=`<table><thead><tr><th>Recipient</th><th>Album</th><th class=n>Opens</th><th class=n>Downloads</th><th class=n>Visitors</th><th class=n>Expires</th><th></th></tr></thead><tbody>`+
  d.shares.map(s=>`<tr><td><span class=nm>${esc(s.for||'—')}</span></td><td class=mut>${esc(s.album)}</td>
   <td class=n>${s.opens}</td><td class=n>${s.downloads}</td><td class=n>${s.visitors}</td>
   <td class="n mut">${esc(s.expires_in)}</td><td class=n><button class=close data-k="${esc(s.key)}">Close</button></td></tr>`).join('')+`</tbody></table>`;
 document.querySelectorAll('.close[data-k]').forEach(b=>b.onclick=()=>closeShare(b.dataset.k))}
async function loadStats(){const a=await j('/stats');
 if(!a.length){$('#stats').innerHTML='<div class=empty>No activity recorded yet.</div>';return}
 $('#stats').innerHTML=`<table><thead><tr><th>Album</th><th class=n>Shares</th><th class=n>Opens</th><th class=n>Photo views</th><th class=n>Downloads</th><th class=n>Visitors</th></tr></thead><tbody>`+
  a.map(r=>`<tr><td class=nm>${esc(r.album)}</td><td class=n>${r.shares}</td><td class=n>${r.opens}</td>
   <td class=n>${r.views}</td><td class="n big">${r.downloads}</td><td class=n>${r.visitors}</td></tr>`).join('')+`</tbody></table>`}
async function closeShare(k){if(!confirm('Close this share? The link will become unavailable.'))return;
 const d=await j('/shares/'+k+'/close',{method:'POST',headers:{'X-PS':'1'}});toast(d.message||'closed');loadShares()}
$('#create').onclick=async()=>{const b=$('#create');b.disabled=true;b.textContent='…';
 const body={album:$('#album').value,ttl:$('#ttl').value,for:$('#for').value};
 const d=await j('/shares/open',{method:'POST',headers:{'Content-Type':'application/json','X-PS':'1'},body:JSON.stringify(body)});
 b.disabled=false;b.textContent='Create';
 if(d.link){$('#rlink').textContent=d.link;$('#rpw').textContent=d.password;$('#result').classList.add('show');toast('Share created');loadShares()}else toast(d.message||'error')};
document.querySelectorAll('.copy').forEach(b=>b.onclick=()=>{navigator.clipboard.writeText($('#'+b.dataset.c).textContent);toast('copied ✓')});
function refresh(){loadShares();loadStats()}
loadAlbums();refresh();setInterval(refresh,15000);
</script></body></html>"""


def _devhub():
    active = len(_immich_shares() or [])
    af = _authfail_15m()
    dls = sum(a["downloads"] for a in _album_stats())
    metrics = [
        {
            "id": "active",
            "label": "Active shares",
            "value": str(active),
            "type": "text",
        },
        {
            "id": "auth_fail",
            "label": "Password failures /15 min",
            "value": str(af),
            "type": "text",
        },
        {"id": "downloads", "label": "Downloads", "value": str(dls), "type": "text"},
        {"id": "tunnel", "label": "Tunnel WG", "value": _tunnel(), "type": "text"},
    ]
    return {
        "devhub": 1,
        "id": "photo-share",
        "name": "Photo Share",
        "version": "2.0.0",
        "status": "ok",
        "metrics": metrics,
        "services": [],
    }


def _run_cli(args, timeout=180):
    p = subprocess.run([CLI] + args, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr


class H(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    def _security_headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
            "connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; "
            "base-uri 'none'; form-action 'self'",
        )

    def _json(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self._security_headers()
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _html(self, s):
        b = s.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self._security_headers()
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass

    def _host_ok(self):
        host = self.headers.get("Host", "").rsplit(":", 1)[0].strip("[]").lower()
        return host in ALLOWED_HOSTS

    def _auth_ok(self):
        if not MONITOR_PASSWORD:
            return True
        client = self.client_address[0]
        now = time.monotonic()
        with _auth_lock:
            recent = [
                stamp for stamp in _auth_failures.get(client, []) if now - stamp < 300
            ]
            _auth_failures[client] = recent
            if len(recent) >= 10:
                return False
        value = self.headers.get("Authorization", "")
        expected = base64.b64encode(
            f"{MONITOR_USER}:{MONITOR_PASSWORD}".encode()
        ).decode()
        valid = hmac.compare_digest(value, f"Basic {expected}")
        with _auth_lock:
            if valid:
                _auth_failures.pop(client, None)
            else:
                _auth_failures.setdefault(client, []).append(now)
        return valid

    def _access_ok(self):
        if not self._host_ok():
            self._json(403, {"error": "forbidden host"})
            return False
        if not self._auth_ok():
            body = json.dumps({"error": "authentication required"}).encode()
            self.send_response(401)
            self.send_header(
                "WWW-Authenticate", 'Basic realm="immich-share", charset="UTF-8"'
            )
            self.send_header("Content-Type", "application/json")
            self._security_headers()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return False
        return True

    def do_GET(self):
        if not self._access_ok():
            return
        if self.path == "/health":
            return self._json(200, {"ok": True})
        if self.path in ("/", ""):
            return self._html(PAGE)
        if self.path == "/devhub":
            try:
                return self._json(200, _devhub())
            except Exception:
                return self._json(
                    200,
                    {
                        "devhub": 1,
                        "id": "photo-share",
                        "name": "Photo Share",
                        "status": "error",
                        "metrics": [],
                        "services": [],
                    },
                )
        if self.path == "/albums":
            try:
                return self._json(200, _albums())
            except Exception:
                return self._json(200, [])
        if self.path == "/shares":
            try:
                sh = []
                for s in _immich_shares():
                    st = _share_stats(s["key"])
                    sh.append({**s, **st})
                return self._json(
                    200,
                    {
                        "shares": sh,
                        "tunnel": _tunnel(),
                        "peers": int(_meta_get("peers_up", 2) or 2),
                        "auth_fail": _authfail_15m(),
                    },
                )
            except Exception as e:
                return self._json(
                    200,
                    {
                        "shares": [],
                        "tunnel": "?",
                        "peers": 0,
                        "auth_fail": 0,
                        "error": str(e),
                    },
                )
        if self.path == "/stats":
            try:
                return self._json(200, _album_stats())
            except Exception:
                return self._json(200, [])
        self._json(404, {"error": "not found"})

    def do_POST(self):
        if not self._access_ok():
            return
        # CSRF: a custom header cannot be sent in a simple cross-origin request;
        # it would require a preflight that this server does not allow.
        if self.headers.get("X-PS") != "1":
            return self._json(403, {"message": "forbidden"})
        try:
            n = int(self.headers.get("Content-Length", 0) or 0)
        except ValueError:
            return self._json(400, {"message": "bad length"})
        if n > 65536:
            return self._json(413, {"message": "payload too large"})
        try:
            raw = self.rfile.read(n).decode("utf-8", "replace") if n else "{}"
            data = json.loads(raw) if raw.strip() else {}
        except (ValueError, OSError):
            data = {}
        if self.path == "/shares/open":
            album = (data.get("album") or "").strip()
            ttl = (data.get("ttl") or "48h").strip()
            who = (data.get("for") or "").strip()
            if not album:
                return self._json(400, {"message": "❌ Album is required"})
            if not TTL_RE.match(ttl):
                return self._json(400, {"message": f"❌ Invalid duration '{ttl}'"})
            args = ["open", album, "--ttl", ttl] + (["--for", who] if who else [])
            try:
                rc, out, err = _run_cli(args)
            except Exception as ex:
                return self._json(200, {"message": f"❌ execution: {str(ex)[:120]}"})
            if rc != 0:
                return self._json(200, {"message": f"❌ {(err or out).strip()[:200]}"})
            link = next(
                (
                    line.split(":", 1)[1].strip()
                    for line in out.splitlines()
                    if "Link" in line
                ),
                "",
            )
            pw = next(
                (
                    line.split(":", 1)[1].strip()
                    for line in out.splitlines()
                    if "Password" in line
                ),
                "",
            )
            return self._json(
                200, {"message": "✅ Share created", "link": link, "password": pw}
            )
        m = re.match(r"^/shares/([A-Za-z0-9_-]{8,128})/close$", self.path)
        if m:
            key = m.group(1)
            if not KEY_RE.match(key):
                return self._json(400, {"message": "❌ invalid key"})
            try:
                rc, out, err = _run_cli(["close", key])
            except Exception as ex:
                return self._json(200, {"message": f"❌ execution: {str(ex)[:120]}"})
            if rc != 0:
                return self._json(200, {"message": f"❌ {(err or out).strip()[:200]}"})
            return self._json(200, {"message": "✅ Share closed"})
        self._json(404, {"message": "not found"})


if __name__ == "__main__":
    _init_db()
    threading.Thread(target=_ingest_loop, daemon=True).start()
    print(f"[photo-share-monitor] :{PORT} (db {DB})")
    print(f"[photo-share-monitor] bind {BIND}:{PORT}")
    ThreadingHTTPServer((BIND, PORT), H).serve_forever()
