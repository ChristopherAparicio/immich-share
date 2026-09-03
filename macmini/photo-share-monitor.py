#!/usr/bin/env python3
"""photo-share-monitor — console and telemetry for immich-share.

- Serves a console to create, list, and close shares and view album statistics.
- Continuously ingests the Caddy access log over the tunnel into local SQLite,
  retaining opens, downloads, and unique visitors after a share expires.
  Client addresses are hashed for privacy.
- Exposes /devhub for dashboards and infrastructure alerts.
Actions call the immich-share CLI without shell=True. Tailnet only.

Importing this module has no side effects: configuration, storage and the
listening socket are created by ``main()`` (or ``load_settings()`` +
``activate()`` in tests).
"""

from __future__ import annotations  # Compatibility with the Mac mini system Python 3.9.

import base64
import configparser
import hashlib
import hmac
import importlib.machinery
import importlib.util
import ipaddress
import json
import os
import re
import secrets
import socket
import sqlite3
import stat
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

PORT = 9097
ROOT = Path(__file__).resolve().parents[1]
CLI = str(ROOT / "immich-share")
TTL_RE = re.compile(r"^\d+[hdj]$")
INGEST_EVERY = 45
# Telemetry older than this is reported as stale rather than trusted.
STALE_AFTER = 3 * INGEST_EVERY
LOCKOUT_FAILURES = 10
LOCKOUT_WINDOW = 300
LOG_REPEAT_EVERY = 300
MAX_BODY = 65536


def _load_cli_module():
    """Import the CLI as a module so its config, secret and Immich code is reused."""
    loader = importlib.machinery.SourceFileLoader("immich_share_cli", CLI)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


cli = _load_cli_module()
KEY_RE = cli.KEY_RE
UUID_RE = cli.UUID_RE

# Runtime settings, populated by activate(); None until then.
S: SimpleNamespace | None = None

_dblock = threading.Lock()
_auth_lock = threading.Lock()
_auth_failures: dict[str, list[tuple[float, bytes]]] = {}
_log_lock = threading.Lock()
_log_last: dict[str, float] = {}
_log_suppressed: dict[str, int] = {}


# ─── Logging (stderr, rate limited per category) ──────────────────


def log(kind, message, every=LOG_REPEAT_EVERY):
    """Write one line to stderr, repeating a category at most once per ``every`` s."""
    now = time.monotonic()
    with _log_lock:
        last = _log_last.get(kind)
        if last is not None and now - last < every:
            _log_suppressed[kind] = _log_suppressed.get(kind, 0) + 1
            return False
        suppressed = _log_suppressed.pop(kind, 0)
        _log_last[kind] = now
    suffix = f" ({suppressed} similar messages suppressed)" if suppressed else ""
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(
        f"{stamp} [photo-share-monitor] {kind}: {message}{suffix}",
        file=sys.stderr,
        flush=True,
    )
    return True


def _exc_summary(exc):
    return f"{type(exc).__name__}: {str(exc)[:200]}"


# ─── Settings ─────────────────────────────────────────────────────

# Same shape cli.Edge accepts: an SSH alias or user@host (bracketed IPv6 allowed).
_SSH_TARGET_RE = re.compile(r"(?:[A-Za-z0-9_.-]+@)?(?:[A-Za-z0-9_.-]+|\[[0-9A-Fa-f:]+\])")


def _ssh_target(cfg):
    """The [vps] ssh target the monitor polls.

    Only this key is needed here; constructing cli.Edge would also demand the
    caddy_*_cmd and [nas] forward_*_cmd keys that a monitor-only host may omit.
    """
    try:
        target = cfg["vps"]["ssh"].strip()
    except KeyError as exc:
        raise RuntimeError("[vps] ssh is required") from exc
    if not _SSH_TARGET_RE.fullmatch(target):
        raise RuntimeError("invalid [vps] ssh target; use an SSH alias or user@host")
    return target


def load_settings(config_path=None, environ=None):
    """Parse and validate configuration without touching the filesystem otherwise.

    Raises RuntimeError for monitor-specific problems and SystemExit (via the
    CLI's die()) for problems the CLI itself would refuse.
    """
    environ = os.environ if environ is None else environ
    cfg = cli.load_config(config_path)
    immich = cli.Immich(cfg)
    vps_ssh = _ssh_target(cfg)

    # Tailnet-only bind. The safe default is 127.0.0.1; use the tailnet address
    # to access the console from another device. Never use a wildcard.
    bind = environ.get("PHOTO_SHARE_BIND") or cfg.get(
        "monitor", "bind", fallback="127.0.0.1"
    )
    bind = bind.strip()
    if not bind:
        raise RuntimeError("[monitor] bind must not be empty")
    try:
        bind_addr = ipaddress.ip_address(bind.strip("[]"))
    except ValueError:
        bind_addr = None
    if bind == "*" or (bind_addr is not None and bind_addr.is_unspecified):
        raise RuntimeError("wildcard monitor binds are forbidden")
    if bind_addr is not None:
        bind = str(bind_addr)
    bind_is_loopback = cli._loopback_host(bind)

    # DNS rebinding defense: accept only these Host values. A browser cannot
    # forge Host, so a malicious page rebound to localhost or the tailnet address
    # is rejected. Add a tailnet hostname to [monitor] allowed_hosts when needed.
    extra_hosts = {
        h.strip().lower()
        for h in cfg.get("monitor", "allowed_hosts", fallback="").split(",")
        if h.strip()
    }
    allowed_hosts = {"127.0.0.1", "localhost", "::1", bind.lower()} | extra_hosts

    user = cfg.get("monitor", "username", fallback="immich-share")
    password_path = cfg.get("monitor", "password_file", fallback="").strip()
    if not password_path:
        raise RuntimeError(
            "the monitor requires [monitor] password_file, including on loopback"
        )
    password = cli.read_private_secret(
        Path(password_path).expanduser(), "monitor password"
    )
    if len(password) < 16:
        raise RuntimeError("monitor password must contain at least 16 characters")
    if not bind_is_loopback and not cfg.getboolean(
        "monitor", "allow_http_over_private_tunnel", fallback=False
    ):
        raise RuntimeError(
            "a non-loopback monitor bind requires explicit confirmation of an encrypted private tunnel"
        )
    retention_days = cfg.getint("monitor", "telemetry_retention_days", fallback=90)
    if not 1 <= retention_days <= 3650:
        raise RuntimeError("telemetry_retention_days must be between 1 and 3650")
    expected_peers = cfg.getint("controller", "expected_wireguard_peers", fallback=2)
    if not 1 <= expected_peers <= 64:
        raise RuntimeError("expected_wireguard_peers must be between 1 and 64")

    data_dir = Path.home() / "photo-share-monitor"
    return SimpleNamespace(
        cfg=cfg,
        immich=immich,
        vps_ssh=vps_ssh,
        bind=bind,
        port=int(environ.get("PHOTO_SHARE_PORT") or PORT),
        allowed_hosts=allowed_hosts,
        user=user,
        password=password,
        retention_days=retention_days,
        expected_peers=expected_peers,
        data_dir=data_dir,
        db=data_dir / "telemetry.db",
        salt=None,
    )


def _salt_uninitialised(path):
    """True when no salt exists yet or a crashed first start left an empty file."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return True
    return stat.S_ISREG(info.st_mode) and info.st_size == 0


def _load_salt(path):
    """Create the client-address hashing salt privately once; never share it.

    The salt is written to a private sibling file, fsynced and renamed into
    place, so a crash can never leave a permanently empty ``ip.salt`` behind.
    """
    if _salt_uninitialised(path):
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        try:
            fd = os.open(tmp, flags, 0o600)
        except FileExistsError:
            # Leftover of an earlier crash under a recycled pid: it holds no
            # secret anyone depends on, so start over.
            os.unlink(tmp)
            fd = os.open(tmp, flags, 0o600)
        try:
            with os.fdopen(fd, "w") as handle:
                handle.write(secrets.token_hex(16))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    return cli.read_private_secret(path, "telemetry salt")


def activate(settings):
    """Install settings globally and prepare private storage."""
    global S
    settings.data_dir.mkdir(exist_ok=True, mode=0o700)
    settings.data_dir.chmod(0o700)
    settings.salt = _load_salt(settings.data_dir / "ip.salt")
    S = settings
    _init_db()
    return settings


# ─── SQLite ───────────────────────────────────────────────────────


def _db():
    c = sqlite3.connect(S.db, timeout=10)
    c.row_factory = sqlite3.Row
    return c


@contextmanager
def _conn():
    """Serialized connection that commits on success and always closes."""
    with _dblock:
        c = _db()
        try:
            with c:
                yield c
        finally:
            c.close()


def _init_db():
    with _conn() as c:
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
    S.db.chmod(0o600)


def _purge_old_events():
    cutoff = time.time() - S.retention_days * 86400
    with _conn() as c:
        c.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
        # A share row is history for its events; drop it only once none remain.
        c.execute(
            "DELETE FROM shares WHERE last_seen < ? "
            "AND key NOT IN (SELECT DISTINCT key FROM events)",
            (cutoff,),
        )


def _meta_get(k, default=None):
    with _conn() as c:
        r = c.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
        return r["v"] if r else default


def _meta_rows(c, keys):
    """Several meta values in one query, as a dict (missing keys are absent)."""
    marks = ",".join("?" * len(keys))
    return {
        r["k"]: r["v"]
        for r in c.execute(f"SELECT k, v FROM meta WHERE k IN ({marks})", tuple(keys))
    }


def _meta_put(c, k, v):
    c.execute(
        "INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=?",
        (k, str(v), str(v)),
    )


def _meta_set(k, v):
    with _conn() as c:
        _meta_put(c, k, v)


def _iphash(ip):
    return hashlib.sha256(f"{S.salt}:{ip}".encode()).hexdigest()[:16]


# ─── Immich (through the CLI client) ──────────────────────────────


def _immich_shares():
    """Active links as shown by the console. May raise SystemExit via die()."""
    out, now = [], datetime.now(timezone.utc)
    for link in S.immich.list_links() or []:
        exp = link.get("expiresAt")
        expd = datetime.fromisoformat(exp.replace("Z", "+00:00")) if exp else None
        if expd is not None and expd < now:
            continue
        key = link.get("key", "")
        if not isinstance(key, str) or not KEY_RE.match(key):
            continue
        out.append(
            {
                "key": key,
                "for": link.get("description") or "",
                "album": (link.get("album") or {}).get("albumName", ""),
                "expires_in": _human_delta(expd - now) if expd else "∞",
            }
        )
    return out


def _albums():
    # The CLI client exposes no album listing; its authenticated call helper is
    # reused so URL, key handling and error policy stay in one place.
    albums = S.immich._call("GET", "/albums") or []
    rows = []
    for album in albums:
        if not isinstance(album, dict):
            continue
        album_id = str(album.get("id", ""))
        if not UUID_RE.fullmatch(album_id):
            continue
        rows.append(
            (str(album.get("albumName", "")), album.get("assetCount"), album_id)
        )
    return sorted(rows)


def _human_delta(td):
    s = int(td.total_seconds())
    if s < 3600:
        return f"{s // 60} min"
    if s < 86400:
        return f"{s // 3600} h"
    return f"{s // 86400} d"


# Actual IPP routes observed on 2026-08-25: the size segment conveys intent.
_SIZE_ACTION = {"thumbnail": "thumb", "preview": "view", "original": "download"}
_LOG_ACTIONS = {"gallery", "view", "download", "thumb"}


def _share_ref(key):
    return hashlib.sha256(key.encode()).hexdigest()[:16]


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
            S.vps_ssh,
            "sudo -n wg show wg0 latest-handshakes; echo '==='; "
            "docker exec caddy tail -n 8000 /data/access.log 2>/dev/null",
        ],
        capture_output=True,
        text=True,
        timeout=20,
    )
    if p.returncode != 0:
        raise RuntimeError(
            f"ssh exit {p.returncode}: {(p.stderr or '').strip()[:200] or 'no output'}"
        )
    wg, sep, log_tail = p.stdout.partition("===\n")
    if not sep:
        raise RuntimeError("unexpected remote output (missing separator)")
    return wg, log_tail


def _count_peers(wg, now):
    peers = 0
    for ln in wg.strip().splitlines():
        stamp = ln.split("\t")[-1]
        if stamp.isdigit() and now - int(stamp) < 300:
            peers += 1
    return peers


def _ingest_once():
    try:
        wg, log_tail = _vps_fetch()
    except (subprocess.SubprocessError, OSError, RuntimeError) as exc:
        log("ingest", f"VPS telemetry fetch failed: {_exc_summary(exc)}")
        return False
    now = time.time()
    peers_up = _count_peers(wg, now)
    last_ts = float(_meta_get("last_event_ts", 0) or 0)
    # May raise SystemExit (die() in the CLI client); nothing is stamped then.
    shares = {s["key"]: s for s in _immich_shares()}
    share_refs = {_share_ref(key): key for key in shares}
    rows, maxts = [], last_ts
    for line in log_tail.splitlines():
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if not isinstance(e, dict):
            continue
        ts = e.get("ts", 0)
        if not isinstance(ts, (int, float)) or ts <= last_ts:
            continue
        maxts = max(maxts, ts)
        req = e.get("request") or {}
        if not isinstance(req, dict):
            req = {}
        status = e.get("status")
        ip = _iphash(str(req.get("client_ip") or req.get("remote_ip") or "?"))
        if status == 429:  # Caddy rate limit; possible password brute force.
            rows.append((ts, "", ip, "ratelimit", 429))
            continue
        key = share_refs.get(e.get("share_ref"))
        action = e.get("share_action")
        if not key or action not in _LOG_ACTIONS:
            # Historical entries created before full URI redaction used the path.
            key, action = _classify(
                str(req.get("method", "")), str(req.get("uri", ""))
            )
        if not key or status not in (200, 206):
            continue
        rows.append((ts, key, ip, action, status))
    with _conn() as c:
        if rows:
            c.executemany(
                "INSERT INTO events(ts,key,ip_hash,action,status) VALUES(?,?,?,?,?)",
                rows,
            )
        # Upsert every cycle so album/recipient labels stay current even when
        # no visitor activity occurred.
        for k, s in shares.items():
            c.execute(
                """INSERT INTO shares(key,album,for_label,first_seen,last_seen)
                         VALUES(?,?,?,?,?) ON CONFLICT(key) DO UPDATE SET
                         album=excluded.album, for_label=excluded.for_label, last_seen=excluded.last_seen""",
                (k, s["album"], s["for"], now, now),
            )
        # Freshness is recorded in the same transaction as the data it vouches
        # for: a failed Immich half must never make the telemetry look fresh.
        _meta_put(c, "peers_up", peers_up)
        _meta_put(c, "last_ingest", int(now))
        if rows:
            _meta_put(c, "last_event_ts", maxts)
    return True


def _ingest_loop():
    while True:
        try:
            _ingest_once()
            last_purge = float(_meta_get("last_purge", 0) or 0)
            if time.time() - last_purge > 86400:
                _purge_old_events()
                _meta_set("last_purge", int(time.time()))
        except SystemExit as exc:
            # die() inside the CLI client (for example Immich unreachable).
            log("ingest", f"CLI helper aborted during ingest (exit {exc.code})")
        except Exception as exc:
            log("ingest", f"ingest cycle failed: {_exc_summary(exc)}")
        time.sleep(INGEST_EVERY)


# ─── Statistics queries ───────────────────────────────────────────


def _share_stats(c, keys):
    """Per-share counters for ``keys`` with a single GROUP BY (uses ix_events_key)."""
    stats = {k: {"opens": 0, "views": 0, "downloads": 0, "visitors": 0} for k in keys}
    if not stats:
        return stats
    marks = ",".join("?" * len(stats))
    rows = c.execute(
        f"""SELECT key,
        SUM(action='gallery') opens, SUM(action='view') views,
        SUM(action='download') downloads, COUNT(DISTINCT ip_hash) visitors
        FROM events WHERE key IN ({marks}) GROUP BY key""",
        tuple(stats),
    )
    for r in rows:
        stats[r["key"]] = {
            "opens": r["opens"] or 0,
            "views": r["views"] or 0,
            "downloads": r["downloads"] or 0,
            "visitors": r["visitors"] or 0,
        }
    return stats


def _console_snapshot(share_keys=()):
    """Telemetry, recent 429 count and per-share statistics from one connection."""
    with _conn() as c:
        meta = _meta_rows(c, ("last_ingest", "peers_up"))
        ratelimit = _ratelimit_15m(c)
        stats = _share_stats(c, share_keys)
    return _telemetry(meta=meta), ratelimit, stats


def _album_stats():
    with _conn() as c:
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


def _telemetry(now=None, meta=None):
    """Tunnel telemetry with explicit freshness; peers are never assumed."""
    now = time.time() if now is None else now
    if meta is None:
        with _conn() as c:
            meta = _meta_rows(c, ("last_ingest", "peers_up"))
    last = meta.get("last_ingest")
    peers = meta.get("peers_up")
    result = {
        "status": "unknown",
        "peers": None,
        "expected_peers": S.expected_peers,
        "age": None,
        "stale_after": STALE_AFTER,
    }
    if last is None or peers is None:
        return result
    try:
        age = max(0, int(now - float(last)))
        peers_up = int(peers)
    except ValueError:
        return result
    result["age"] = age
    if age > STALE_AFTER:
        result["status"] = "stale"
        return result
    result["status"] = "ok"
    result["peers"] = peers_up
    return result


def _tunnel(tel=None):
    tel = _telemetry() if tel is None else tel
    if tel["status"] == "ok":
        return f"{tel['peers']}/{tel['expected_peers']}"
    if tel["status"] == "stale":
        return f"stale ({_human_delta(timedelta(seconds=tel['age']))})"
    return "unknown"


def _ratelimit_15m(c):
    """Caddy 429 responses recorded in the last 15 minutes."""
    r = c.execute(
        "SELECT COUNT(*) n FROM events WHERE action='ratelimit' AND ts>?",
        (time.time() - 900,),
    ).fetchone()
    return r["n"] or 0


# ─── HTML console ─────────────────────────────────────────────────

SCRIPT = r"""
const $=s=>document.querySelector(s),esc=s=>String(s==null?'':s).replace(/[<>&"']/g,c=>({'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;',"'":'&#39;'}[c]));
function toast(m){const t=$('#toast');t.textContent=m;t.classList.add('show');clearTimeout(t._);t._=setTimeout(()=>t.classList.remove('show'),1900)}
async function j(u,o){const r=await fetch(u,o);try{return await r.json()}catch(e){return {error:'invalid response'}}}
async function loadAlbums(){const a=await j('/albums');if(!Array.isArray(a)){toast(a.error||'albums unavailable');return}
 $('#album').innerHTML=a.map(x=>`<option value="${esc(x[2])}">${esc(x[0])} · ${esc(x[1]==null?'?':x[1])}</option>`).join('')}
function pill(d){const t=d.telemetry||{status:'unknown'};
 const w=t.status!=='ok'||t.peers==null||t.peers<t.expected_peers||d.ratelimit_15m>0;
 $('#pill').firstElementChild.className='dot'+(w?' warn':'');
 const tun=t.status==='ok'?`tunnel ${esc(d.tunnel)}`:`tunnel ${esc(d.tunnel)} (telemetry ${esc(t.status)})`;
 $('#pilltxt').textContent=`${tun} · ${d.ratelimit_15m==null?'?':d.ratelimit_15m} rate-limit hits/15 min`}
async function loadShares(){const d=await j('/shares');if(d.telemetry)pill(d);
 if(d.error||!Array.isArray(d.shares)){$('#shares').innerHTML=`<div class=empty>${esc(d.error||'unavailable')}</div>`;return}
 if(!d.shares.length){$('#shares').innerHTML='<div class=empty>No active shares — no public attack surface.</div>';return}
 $('#shares').innerHTML=`<table><thead><tr><th>Recipient</th><th>Album</th><th class=n>Opens</th><th class=n>Downloads</th><th class=n>Visitors</th><th class=n>Expires</th><th></th></tr></thead><tbody>`+
  d.shares.map(s=>`<tr><td><span class=nm>${esc(s.for||'—')}</span></td><td class=mut>${esc(s.album)}</td>
   <td class=n>${esc(s.opens)}</td><td class=n>${esc(s.downloads)}</td><td class=n>${esc(s.visitors)}</td>
   <td class="n mut">${esc(s.expires_in)}</td><td class=n><button class=close data-k="${esc(s.key)}">Close</button></td></tr>`).join('')+`</tbody></table>`;
 document.querySelectorAll('.close[data-k]').forEach(b=>b.onclick=()=>closeShare(b.dataset.k))}
async function loadStats(){const a=await j('/stats');if(!Array.isArray(a)){$('#stats').innerHTML=`<div class=empty>${esc(a.error||'unavailable')}</div>`;return}
 if(!a.length){$('#stats').innerHTML='<div class=empty>No activity recorded yet.</div>';return}
 $('#stats').innerHTML=`<table><thead><tr><th>Album</th><th class=n>Shares</th><th class=n>Opens</th><th class=n>Photo views</th><th class=n>Downloads</th><th class=n>Visitors</th></tr></thead><tbody>`+
  a.map(r=>`<tr><td class=nm>${esc(r.album)}</td><td class=n>${esc(r.shares)}</td><td class=n>${esc(r.opens)}</td>
   <td class=n>${esc(r.views)}</td><td class="n big">${esc(r.downloads)}</td><td class=n>${esc(r.visitors)}</td></tr>`).join('')+`</tbody></table>`}
async function closeShare(k){if(!confirm('Close this share? The link will become unavailable.'))return;
 const d=await j('/shares/'+encodeURIComponent(k)+'/close',{method:'POST',headers:{'X-PS':'1'}});toast(d.message||d.error||'closed');loadShares()}
$('#create').onclick=async()=>{const b=$('#create');b.disabled=true;b.textContent='…';
 const body={album:$('#album').value,ttl:$('#ttl').value,for:$('#for').value};
 const d=await j('/shares/open',{method:'POST',headers:{'Content-Type':'application/json','X-PS':'1'},body:JSON.stringify(body)});
 b.disabled=false;b.textContent='Create';
 if(d.link){$('#rlink').textContent=d.link;$('#rpw').textContent=d.password;$('#result').classList.add('show');toast('Share created');loadShares()}else toast(d.message||d.error||'error')};
document.querySelectorAll('.copy').forEach(b=>b.onclick=()=>{navigator.clipboard.writeText($('#'+b.dataset.c).textContent);toast('copied ✓')});
function refresh(){loadShares();loadStats()}
loadAlbums();refresh();setInterval(refresh,15000);
"""

PAGE_TEMPLATE = r"""<!doctype html><html lang=en><head><meta charset=utf-8>
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
<script>@@SCRIPT@@</script></body></html>"""

PAGE = PAGE_TEMPLATE.replace("@@SCRIPT@@", SCRIPT)
# CSP hash of the single inline script: XSS cannot execute injected script.
SCRIPT_HASH = "sha256-" + base64.b64encode(
    hashlib.sha256(SCRIPT.encode("utf-8")).digest()
).decode()
CSP = (
    f"default-src 'self'; style-src 'unsafe-inline'; script-src '{SCRIPT_HASH}'; "
    "connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; "
    "base-uri 'none'; form-action 'self'"
)


def _devhub():
    tel, ratelimit, _ = _console_snapshot()
    dls = sum(a["downloads"] for a in _album_stats())
    active = len(_immich_shares())
    metrics = [
        {"id": "active", "label": "Active shares", "value": str(active), "type": "text"},
        {
            "id": "ratelimit_429",
            "label": "Caddy 429 rate-limit hits /15 min",
            "value": str(ratelimit),
            "type": "text",
        },
        {"id": "downloads", "label": "Downloads", "value": str(dls), "type": "text"},
        {"id": "tunnel", "label": "Tunnel WG", "value": _tunnel(tel), "type": "text"},
        {
            "id": "telemetry",
            "label": "Telemetry freshness",
            "value": tel["status"],
            "type": "text",
        },
    ]
    healthy = (
        tel["status"] == "ok"
        and tel["peers"] is not None
        and tel["peers"] >= tel["expected_peers"]
    )
    return {
        "devhub": 1,
        "id": "photo-share",
        "name": "Photo Share",
        "version": "2.1.0",
        "status": "ok" if healthy else "warn",
        "telemetry": tel,
        "metrics": metrics,
        "services": [],
    }


# ─── CLI invocation ───────────────────────────────────────────────


def _run_cli(args, timeout=180):
    p = subprocess.run([CLI] + args, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr


def parse_open_output(stdout):
    """Validate the JSON object printed by ``immich-share open --json``."""
    try:
        obj = json.loads(stdout)
    except ValueError as exc:
        raise ValueError("stdout is not JSON") from exc
    if not isinstance(obj, dict):
        raise ValueError("stdout is not a JSON object")
    key = obj.get("key")
    link = obj.get("link")
    password = obj.get("password")
    if not isinstance(key, str) or not KEY_RE.match(key):
        raise ValueError("missing or invalid key")
    if not isinstance(link, str) or not link.startswith("https://"):
        raise ValueError("missing or invalid link")
    if not isinstance(password, str) or not password:
        raise ValueError("missing password")
    expires = obj.get("expiresAt")
    album = obj.get("album")
    return {
        "key": key,
        "link": link,
        "password": password,
        "expiresAt": expires if isinstance(expires, str) else "",
        "album": album.get("name", "") if isinstance(album, dict) else "",
        "allowDownload": bool(obj.get("allowDownload", True)),
    }


_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


def _cli_error_message(stderr, stdout):
    """Operator-facing summary of a failed CLI run: the last non-empty line."""
    text = stderr or stdout or ""
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    last = lines[-1] if lines else "command failed"
    last = _CONTROL_RE.sub(" ", last)
    if last.startswith("❌"):
        last = last[1:].strip()
    return last[:200]


# ─── HTTP ─────────────────────────────────────────────────────────


class H(BaseHTTPRequestHandler):
    server_version = "photo-share-monitor"
    sys_version = ""

    def version_string(self):
        return self.server_version

    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    # Request lines are not logged: paths embed share keys.
    def log_request(self, *a):
        pass

    def log_error(self, fmt, *a):
        # The stdlib passes (code, message) where message can quote the raw
        # request line; keep only the numeric code.
        code = a[0] if a and isinstance(a[0], int) else None
        log("http", f"code {code}" if code is not None else "request error")

    def send_error(self, code, message=None, explain=None):
        # The default body repeats the request line ("Bad request syntax (...)").
        super().send_error(code, "request rejected", "")

    def log_message(self, fmt, *a):
        log("http", fmt % a if a else fmt)

    def _security_headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", CSP)

    def _send(self, code, body, content_type, extra=()):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        for name, value in extra:
            self.send_header(name, value)
        self._security_headers()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code, obj, extra=()):
        self._send(code, json.dumps(obj).encode(), "application/json", extra)

    def _html(self, s):
        self._send(200, s.encode(), "text/html; charset=utf-8")

    def _host_ok(self):
        host = self.headers.get("Host", "").rsplit(":", 1)[0].strip("[]").lower()
        return host in S.allowed_hosts

    def _auth_ok(self):
        client = self.client_address[0]
        value = self.headers.get("Authorization")
        if value is None:
            # A browser's first request or a cross-site <img> load carries no
            # credentials; that is a challenge, not a failed guess.
            return False
        expected = "Basic " + base64.b64encode(
            f"{S.user}:{S.password}".encode()
        ).decode()
        try:
            valid = hmac.compare_digest(
                value.encode("utf-8", "surrogateescape"), expected.encode("utf-8")
            )
        except (TypeError, UnicodeError):
            valid = False
        try:
            fingerprint = hashlib.sha256(
                value.encode("utf-8", "surrogateescape")
            ).digest()
        except (TypeError, UnicodeError):
            fingerprint = hashlib.sha256(b"invalid-authorization").digest()
        now = time.monotonic()
        with _auth_lock:
            recent = [
                (stamp, digest)
                for stamp, digest in _auth_failures.get(client, [])
                if now - stamp < LOCKOUT_WINDOW
            ]
            if len(recent) >= LOCKOUT_FAILURES:
                # A real lockout is checked before accepting even a correct
                # credential. Further requests do not extend it, so access is
                # restored after the last counted distinct guess expires.
                _auth_failures[client] = recent
                log("auth", f"lockout active for {client}")
                return False
            if valid:
                _auth_failures.pop(client, None)
                return True
            # A stale browser tab replaying one old Basic credential counts as
            # one failed guess. Distinct guesses still trigger the lockout.
            if not any(hmac.compare_digest(digest, fingerprint) for _, digest in recent):
                recent.append((now, fingerprint))
            _auth_failures[client] = recent
            if len(recent) >= LOCKOUT_FAILURES:
                log("auth", f"too many failed logins from {client}; locked out")
        return False

    def _access_ok(self):
        if not self._host_ok():
            self._json(403, {"error": "forbidden host"})
            return False
        if not self._auth_ok():
            self._json(
                401,
                {"error": "authentication required"},
                extra=(
                    (
                        "WWW-Authenticate",
                        'Basic realm="immich-share", charset="UTF-8"',
                    ),
                ),
            )
            return False
        return True

    def _dispatch(self, handler):
        """Run a handler; never leak an exception message to the client."""
        try:
            handler()
        except (BrokenPipeError, ConnectionResetError, socket.timeout):
            pass
        except SystemExit as exc:
            # die() inside the CLI client already wrote its reason to stderr.
            log("handler", f"CLI helper aborted while serving {self.command} (exit {exc.code})")
            self._json(502, {"error": "upstream error"})
        except Exception as exc:
            log("handler", f"unhandled error serving {self.command}: {_exc_summary(exc)}")
            self._json(500, {"error": "internal error"})

    def do_GET(self):
        self._dispatch(self._get)

    def do_POST(self):
        self._dispatch(self._post)

    def _get(self):
        if not self._access_ok():
            return
        if self.path == "/health":
            return self._json(200, {"ok": True})
        if self.path in ("/", ""):
            return self._html(PAGE)
        if self.path == "/devhub":
            try:
                return self._json(200, _devhub())
            except SystemExit as exc:
                log("devhub", f"CLI helper aborted (exit {exc.code})")
            except Exception as exc:
                log("devhub", f"failed: {_exc_summary(exc)}")
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
            return self._json(200, _albums())
        if self.path == "/shares":
            shares, error = [], None
            try:
                shares = _immich_shares()
            except SystemExit as exc:
                log("shares", f"CLI helper aborted listing links (exit {exc.code})")
                error = "Immich unavailable"
            except Exception as exc:
                log("shares", f"listing links failed: {_exc_summary(exc)}")
                error = "Immich unavailable"
            # One sqlite connection for telemetry, 429s and every share's stats.
            tel, ratelimit, stats = _console_snapshot([s["key"] for s in shares])
            base = {
                "tunnel": _tunnel(tel),
                "telemetry": tel,
                "peers": tel["peers"],
                "ratelimit_15m": ratelimit,
            }
            if error is not None:
                return self._json(502, {**base, "shares": [], "error": error})
            sh = [{**s, **stats[s["key"]]} for s in shares]
            return self._json(200, {**base, "shares": sh})
        if self.path == "/stats":
            return self._json(200, _album_stats())
        self._json(404, {"error": "not found"})

    def _read_json_body(self):
        """Return (data, error_response) for a small JSON object body."""
        raw_len = self.headers.get("Content-Length")
        try:
            n = int(raw_len) if raw_len is not None else 0
        except ValueError:
            return None, (400, {"message": "bad length"})
        if n < 0:
            return None, (400, {"message": "bad length"})
        if n > MAX_BODY:
            return None, (413, {"message": "payload too large"})
        if n == 0:
            return {}, None
        try:
            raw = self.rfile.read(n).decode("utf-8")
        except (OSError, UnicodeDecodeError):
            return None, (400, {"message": "bad request body"})
        if not raw.strip():
            return {}, None
        try:
            data = json.loads(raw)
        except ValueError:
            return None, (400, {"message": "bad request body"})
        if not isinstance(data, dict):
            return None, (400, {"message": "bad request body"})
        return data, None

    def _post(self):
        if not self._access_ok():
            return
        # CSRF: a custom header cannot be sent in a simple cross-origin request;
        # it would require a preflight that this server does not allow.
        if self.headers.get("X-PS") != "1":
            return self._json(403, {"message": "forbidden"})
        data, error = self._read_json_body()
        if error is not None:
            return self._json(*error)
        if self.path == "/shares/open":
            album = str(data.get("album") or "").strip()
            ttl = str(data.get("ttl") or "48h").strip()
            who = str(data.get("for") or "").strip()
            if not album:
                return self._json(400, {"message": "❌ Album is required"})
            if not TTL_RE.match(ttl):
                return self._json(400, {"message": "❌ Invalid duration"})
            args = ["open", "--json", f"--ttl={ttl}"]
            if who:
                args.append(f"--for={who}")
            args += ["--", album]
            try:
                rc, out, err = _run_cli(args)
            except (subprocess.SubprocessError, OSError) as exc:
                log("cli", f"open could not run: {_exc_summary(exc)}")
                return self._json(502, {"message": "❌ share tool unavailable"})
            if rc != 0:
                log("cli", f"open exited {rc}: {_cli_error_message(err, '')}")
                return self._json(502, {"message": f"❌ {_cli_error_message(err, out)}"})
            try:
                created = parse_open_output(out)
            except ValueError as exc:
                # Never log stdout: on success it would contain the password.
                log("cli", f"open produced unusable --json output: {exc}")
                return self._json(502, {"message": "❌ share tool returned unexpected output"})
            return self._json(
                200,
                {
                    "message": "✅ Share created",
                    "link": created["link"],
                    "password": created["password"],
                    "expiresAt": created["expiresAt"],
                    "album": created["album"],
                },
            )
        m = re.match(r"^/shares/([A-Za-z0-9_-]{8,128})/close$", self.path)
        if m:
            key = m.group(1)
            if not KEY_RE.match(key):
                return self._json(400, {"message": "❌ invalid key"})
            try:
                rc, out, err = _run_cli(["close", "--", key])
            except (subprocess.SubprocessError, OSError) as exc:
                log("cli", f"close could not run: {_exc_summary(exc)}")
                return self._json(502, {"message": "❌ share tool unavailable"})
            if rc != 0:
                log("cli", f"close exited {rc}: {_cli_error_message(err, out)}")
                return self._json(502, {"message": f"❌ {_cli_error_message(err, out)}"})
            return self._json(200, {"message": "✅ Share closed"})
        self._json(404, {"message": "not found"})


def make_server(bind, port, handler=H):
    """Bind on IPv4 or IPv6 depending on the configured address."""
    try:
        family = (
            socket.AF_INET6
            if ipaddress.ip_address(bind).version == 6
            else socket.AF_INET
        )
    except ValueError:
        family = socket.AF_INET

    class Server(ThreadingHTTPServer):
        address_family = family
        daemon_threads = True
        allow_reuse_address = True

    return Server((bind, port), handler)


def _config_error(exc):
    if isinstance(exc, KeyError):
        return f"missing configuration key {exc.args[0]!r}" if exc.args else "missing configuration key"
    return str(exc)


def main():
    try:
        settings = load_settings()
        activate(settings)
    except (RuntimeError, KeyError, ValueError, configparser.Error) as exc:
        # A configuration problem is reported once, not as a traceback that
        # launchd would restart into forever.
        print(f"❌ {_config_error(exc)}", file=sys.stderr)
        return 1
    except SystemExit as exc:
        # die() in the CLI helpers (secrets, salt) already explained itself.
        return exc.code if isinstance(exc.code, int) else 1
    threading.Thread(target=_ingest_loop, daemon=True).start()
    server = make_server(S.bind, S.port)
    print(f"[photo-share-monitor] :{S.port} (db {S.db})")
    print(f"[photo-share-monitor] bind {S.bind}:{S.port}")
    print(f"[photo-share-monitor] Server header: {H.server_version}")
    sys.stdout.flush()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
