#!/usr/bin/env python3
"""Roulette server: static frontend + JSON API + Google Sign-In sessions.

Standard library only (Python 3.9+). SQLite storage in ./data/roulette.db.
Config: ./config.local.json {"google_client_id": "..."} or env ROULETTE_GOOGLE_CLIENT_ID.
"""
import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import sqlite3
import sys
import threading
import time
import urllib.request
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("ROULETTE_DATA_DIR", os.path.join(ROOT, "data"))
DB_PATH = os.path.join(DATA_DIR, "roulette.db")
CONFIG_PATH = os.environ.get("ROULETTE_CONFIG", os.path.join(ROOT, "config.local.json"))
HOST = os.environ.get("ROULETTE_HOST", "127.0.0.1")
PORT = int(os.environ.get("ROULETTE_PORT", "8793"))

SESSION_COOKIE = "__Host-roulette_sid"
SESSION_TTL = 90 * 86400
MAX_FOLDERS = 100
MAX_ITEMS = 50
MAX_ITEM_LEN = 100
MAX_NAME_LEN = 40
MAX_HISTORY = 3000
MAX_BODY = 64 * 1024
MAX_IMPORT_BODY = 8 * 1024 * 1024
ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,40}$")
GOOGLE_CERTS_URL = "https://www.googleapis.com/oauth2/v3/certs"
GOOGLE_ISSUERS = ("accounts.google.com", "https://accounts.google.com")
STATIC_FILES = {"/": "index.html", "/index.html": "index.html"}

log = logging.getLogger("roulette")


def now_ms():
    return int(time.time() * 1000)


# --------------------------------------------------------------------------- config
_cfg = {"mtime": object(), "data": {}}
_cfg_lock = threading.Lock()


def config():
    """Re-read config.local.json when it changes (no restart needed)."""
    try:
        mtime = os.stat(CONFIG_PATH).st_mtime
    except OSError:
        mtime = None
    with _cfg_lock:
        if mtime != _cfg["mtime"]:
            data = {}
            if mtime is not None:
                try:
                    with open(CONFIG_PATH, encoding="utf-8") as f:
                        data = json.load(f)
                    if not isinstance(data, dict):
                        data = {}
                except Exception as e:  # noqa: BLE001
                    log.warning("config.local.json unreadable: %s", e)
            _cfg.update(mtime=mtime, data=data)
        data = dict(_cfg["data"])
    cid = (os.environ.get("ROULETTE_GOOGLE_CLIENT_ID") or data.get("google_client_id") or "").strip()
    if cid and not cid.endswith(".apps.googleusercontent.com"):
        log.warning("google_client_id does not look like a Google OAuth client id; ignoring")
        cid = ""
    return {"google_client_id": cid}


# --------------------------------------------------------------------------- Google ID token verification
class TokenError(Exception):
    pass


def b64url_decode(s):
    if not isinstance(s, str) or not re.fullmatch(r"[A-Za-z0-9_-]*", s):
        raise TokenError("bad base64")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64int(s):
    return int.from_bytes(b64url_decode(s), "big")


_jwks = {"keys": {}, "exp": 0.0, "last_fetch": 0.0}
_jwks_lock = threading.Lock()


def _fetch_google_jwks():
    req = urllib.request.Request(GOOGLE_CERTS_URL, headers={"User-Agent": "roulette-server/1"})
    with urllib.request.urlopen(req, timeout=10) as r:
        body = json.loads(r.read())
        cc = r.headers.get("Cache-Control", "")
    m = re.search(r"max-age=(\d+)", cc)
    ttl = min(int(m.group(1)) if m else 3600, 86400)
    keys = {}
    for k in body.get("keys", []):
        if k.get("kty") == "RSA" and k.get("alg", "RS256") == "RS256" and k.get("kid"):
            keys[k["kid"]] = (_b64int(k["n"]), _b64int(k["e"]))
    return keys, ttl


def google_key(kid):
    """Return (n, e) for a Google signing key id, using a cached JWKS (Cache-Control max-age)."""
    with _jwks_lock:
        t = time.time()
        stale = t >= _jwks["exp"]
        unknown = kid not in _jwks["keys"] and t - _jwks["last_fetch"] > 60
        if stale or unknown:
            keys, ttl = _fetch_google_jwks()
            _jwks.update(keys=keys, exp=t + ttl, last_fetch=t)
        return _jwks["keys"].get(kid)


_SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


def rsa_pkcs1v15_sha256_verify(n, e, message, signature):
    """RSASSA-PKCS1-v1_5 verification with SHA-256 (RFC 8017 8.2.2)."""
    k = (n.bit_length() + 7) // 8
    if n.bit_length() < 2048 or len(signature) != k:
        return False
    s = int.from_bytes(signature, "big")
    if s >= n:
        return False
    em = pow(s, e, n).to_bytes(k, "big")
    t = _SHA256_DIGEST_INFO + hashlib.sha256(message).digest()
    if k < len(t) + 11:
        return False
    expected = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return hmac.compare_digest(em, expected)


def verify_google_id_token(token, client_id, key_lookup=None, now=None):
    """Verify a Google ID token (JWT RS256). Returns the claims dict or raises TokenError."""
    if not client_id:
        raise TokenError("login not configured")
    if not isinstance(token, str) or len(token) > 8192:
        raise TokenError("bad token")
    parts = token.split(".")
    if len(parts) != 3:
        raise TokenError("malformed")
    try:
        header = json.loads(b64url_decode(parts[0]))
        claims = json.loads(b64url_decode(parts[1]))
        sig = b64url_decode(parts[2])
    except TokenError:
        raise
    except Exception:
        raise TokenError("malformed")
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise TokenError("malformed")
    if header.get("alg") != "RS256":
        raise TokenError("unexpected alg")
    kid = header.get("kid")
    if not isinstance(kid, str) or not kid:
        raise TokenError("missing kid")
    key = (key_lookup or google_key)(kid)
    if not key:
        raise TokenError("unknown signing key")
    if not rsa_pkcs1v15_sha256_verify(key[0], key[1], (parts[0] + "." + parts[1]).encode("ascii"), sig):
        raise TokenError("bad signature")
    t = time.time() if now is None else now
    if claims.get("iss") not in GOOGLE_ISSUERS:
        raise TokenError("bad issuer")
    if claims.get("aud") != client_id:
        raise TokenError("bad audience")
    exp = claims.get("exp")
    if not isinstance(exp, (int, float)) or exp < t - 30:
        raise TokenError("expired")
    iat = claims.get("iat")
    if isinstance(iat, (int, float)) and iat > t + 300:
        raise TokenError("issued in the future")
    nbf = claims.get("nbf")
    if isinstance(nbf, (int, float)) and nbf > t + 300:
        raise TokenError("not yet valid")
    sub = claims.get("sub")
    if not isinstance(sub, str) or not sub or len(sub) > 255:
        raise TokenError("missing sub")
    return claims


# --------------------------------------------------------------------------- database
SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, sub TEXT UNIQUE NOT NULL, email TEXT, name TEXT, picture TEXT,
  created INTEGER NOT NULL, last_login INTEGER);
CREATE TABLE IF NOT EXISTS sessions(
  id TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created INTEGER NOT NULL, expires INTEGER NOT NULL, last_seen INTEGER, ua TEXT);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS folders(
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, id TEXT NOT NULL,
  position INTEGER NOT NULL DEFAULT 0, name TEXT NOT NULL, items TEXT NOT NULL DEFAULT '[]',
  exclude INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL, updated INTEGER NOT NULL,
  PRIMARY KEY(user_id, id));
CREATE TABLE IF NOT EXISTS spins(
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, folder_id TEXT NOT NULL,
  item TEXT NOT NULL, set_size INTEGER NOT NULL DEFAULT 0, ts INTEGER NOT NULL,
  FOREIGN KEY(user_id, folder_id) REFERENCES folders(user_id, id) ON DELETE CASCADE);
CREATE INDEX IF NOT EXISTS spins_folder ON spins(user_id, folder_id, ts);
"""


def connect():
    c = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    c.execute("PRAGMA busy_timeout=5000")
    return c


def init_db():
    os.makedirs(DATA_DIR, mode=0o700, exist_ok=True)
    c = connect()
    try:
        c.execute("PRAGMA journal_mode=WAL")
        c.executescript(SCHEMA)
    finally:
        c.close()


class Tx:
    def __init__(self, c):
        self.c = c

    def __enter__(self):
        self.c.execute("BEGIN IMMEDIATE")
        return self.c

    def __exit__(self, et, ev, tb):
        self.c.execute("ROLLBACK" if et else "COMMIT")
        return False


# --------------------------------------------------------------------------- validation
class ApiError(Exception):
    def __init__(self, status, code, detail=None):
        super().__init__(code)
        self.status, self.code, self.detail = status, code, detail


def bad(code, detail=None):
    return ApiError(400, code, detail)


def clean_name(v, strict=True):
    if not isinstance(v, str):
        if strict:
            raise bad("invalid_name")
        v = "이름 없는 룰렛"
    v = " ".join(v.split())[:MAX_NAME_LEN]
    if not v:
        if strict:
            raise bad("invalid_name")
        v = "이름 없는 룰렛"
    return v


def clean_item(v, strict=True):
    if not isinstance(v, str):
        raise bad("invalid_item")
    v = v.strip()
    if len(v) > MAX_ITEM_LEN:
        if strict:
            raise bad("item_too_long", MAX_ITEM_LEN)
        v = v[:MAX_ITEM_LEN]
    return v


def clean_items(v, strict=True):
    if not isinstance(v, list):
        raise bad("invalid_items")
    out = [x for x in (clean_item(i, strict) for i in v if isinstance(i, str) or strict) if x]
    if len(out) > MAX_ITEMS:
        if strict:
            raise bad("too_many_items", MAX_ITEMS)
        out = out[:MAX_ITEMS]
    return out


def clean_id(v):
    if not isinstance(v, str) or not ID_RE.match(v):
        raise bad("invalid_id")
    return v


def new_id():
    return secrets.token_hex(8)


# --------------------------------------------------------------------------- data access (always scoped by user_id)
def folder_row(c, uid, fid):
    return c.execute("SELECT * FROM folders WHERE user_id=? AND id=?", (uid, fid)).fetchone()


def folder_json(r, history=None):
    d = {"id": r["id"], "name": r["name"], "items": json.loads(r["items"]), "exclude": bool(r["exclude"]),
         "created": r["created"], "position": r["position"]}
    if history is not None:
        d["history"] = history
    return d


def load_state(c, uid):
    hist = {}
    for s in c.execute("SELECT folder_id, item, set_size, ts FROM spins WHERE user_id=? ORDER BY ts, id", (uid,)):
        hist.setdefault(s["folder_id"], []).append({"t": s["ts"], "w": s["item"], "n": s["set_size"]})
    rows = c.execute("SELECT * FROM folders WHERE user_id=? ORDER BY position, created", (uid,)).fetchall()
    return [folder_json(r, hist.get(r["id"], [])[-MAX_HISTORY:]) for r in rows]


def folder_count(c, uid):
    return c.execute("SELECT COUNT(*) FROM folders WHERE user_id=?", (uid,)).fetchone()[0]


def insert_folder(c, uid, fid, name, items, exclude, created=None):
    pos = c.execute("SELECT COALESCE(MAX(position), -1) + 1 FROM folders WHERE user_id=?", (uid,)).fetchone()[0]
    t = now_ms()
    c.execute("INSERT INTO folders(user_id,id,position,name,items,exclude,created,updated) VALUES(?,?,?,?,?,?,?,?)",
              (uid, fid, pos, name, json.dumps(items, ensure_ascii=False), 1 if exclude else 0, created or t, t))


def trim_history(c, uid, fid):
    c.execute("""DELETE FROM spins WHERE user_id=? AND folder_id=? AND id NOT IN (
                   SELECT id FROM spins WHERE user_id=? AND folder_id=? ORDER BY ts DESC, id DESC LIMIT ?)""",
              (uid, fid, uid, fid, MAX_HISTORY))


def normalize_import(data):
    if not isinstance(data, dict) or not isinstance(data.get("folders"), list):
        raise bad("invalid_import")
    out = []
    lo, hi = 946684800000, now_ms() + 86400000
    for f in data["folders"][:MAX_FOLDERS]:
        if not isinstance(f, dict):
            continue
        fid = f.get("id") if isinstance(f.get("id"), str) and ID_RE.match(f.get("id")) else new_id()
        items = clean_items(f.get("items") if isinstance(f.get("items"), list) else [], strict=False)
        hist = []
        for e in f.get("history") if isinstance(f.get("history"), list) else []:
            if not isinstance(e, dict) or not isinstance(e.get("w"), str):
                continue
            t, n = e.get("t"), e.get("n", 0)
            if isinstance(t, bool) or not isinstance(t, (int, float)) or not lo <= t <= hi:
                continue
            w = e["w"].strip()[:MAX_ITEM_LEN]
            if w:
                hist.append((int(t), w, int(n) if isinstance(n, (int, float)) and not isinstance(n, bool) and 0 <= n <= 1000 else 0))
        hist.sort()
        created = f.get("created") if isinstance(f.get("created"), (int, float)) and lo <= f.get("created") <= hi else None
        out.append({"id": fid, "name": clean_name(f.get("name"), strict=False), "items": items,
                    "exclude": bool(f.get("exclude")), "created": int(created) if created else None,
                    "history": hist[-MAX_HISTORY:]})
    return out


# --------------------------------------------------------------------------- API handlers
def api_config(h, user, body):
    cid = config()["google_client_id"]
    return 200, {"google_client_id": cid or None, "login_enabled": bool(cid)}


def user_json(u):
    return {"email": u["email"], "name": u["name"], "picture": u["picture"]}


def api_me(h, user, body):
    """Session probe: 200 with user=null when logged out (avoids console noise); data APIs return 401."""
    return 200, {"user": user_json(user) if user else None}


_login_hits = {}
_login_lock = threading.Lock()


def _login_rate_ok(ip):
    t = time.time()
    with _login_lock:
        hits = [x for x in _login_hits.get(ip, []) if t - x < 60]
        hits.append(t)
        _login_hits[ip] = hits
        if len(_login_hits) > 10000:
            _login_hits.clear()
        return len(hits) <= 20


def api_login(h, user, body):
    cid = config()["google_client_id"]
    if not cid:
        raise ApiError(503, "login_not_configured")
    if not _login_rate_ok(h.client_ip()):
        raise ApiError(429, "too_many_requests")
    cred = body.get("credential") if isinstance(body, dict) else None
    try:
        claims = verify_google_id_token(cred, cid)
    except TokenError as e:
        log.info("login rejected: %s", e)
        raise ApiError(401, "invalid_token")
    except Exception as e:  # JWKS fetch failure etc.
        log.warning("login verification error: %r", e)
        raise ApiError(502, "verification_unavailable")
    sub = claims["sub"]
    email = claims.get("email") if isinstance(claims.get("email"), str) else None
    name = claims.get("name") if isinstance(claims.get("name"), str) else None
    pic = claims.get("picture") if isinstance(claims.get("picture"), str) and claims["picture"].startswith("https://") else None
    t = now_ms()
    token = secrets.token_urlsafe(32)
    sid = hashlib.sha256(token.encode()).hexdigest()
    c = h.db()
    with Tx(c):
        row = c.execute("SELECT id FROM users WHERE sub=?", (sub,)).fetchone()
        if row:
            uid = row["id"]
            c.execute("UPDATE users SET email=?, name=?, picture=?, last_login=? WHERE id=?", (email, name, pic, t, uid))
        else:
            uid = c.execute("INSERT INTO users(sub,email,name,picture,created,last_login) VALUES(?,?,?,?,?,?)",
                            (sub, email, name, pic, t, t)).lastrowid
        c.execute("INSERT INTO sessions(id,user_id,created,expires,last_seen,ua) VALUES(?,?,?,?,?,?)",
                  (sid, uid, t, t + SESSION_TTL * 1000, t, (h.headers.get("User-Agent") or "")[:200]))
        c.execute("DELETE FROM sessions WHERE expires < ?", (t,))
    h.set_cookie(token, SESSION_TTL)
    return 200, {"user": {"email": email, "name": name, "picture": pic}, "new_user": not row}


def api_logout(h, user, body):
    token = h.session_token()
    if token:
        c = h.db()
        c.execute("DELETE FROM sessions WHERE id=?", (hashlib.sha256(token.encode()).hexdigest(),))
    h.set_cookie("", 0)
    return 200, {"ok": True}


def api_state(h, user, body):
    return 200, {"folders": load_state(h.db(), user["id"])}


def api_folder_create(h, user, body):
    if not isinstance(body, dict):
        raise bad("invalid_body")
    fid = clean_id(body["id"]) if body.get("id") is not None else new_id()
    name = clean_name(body.get("name"))
    items = clean_items(body.get("items", []))
    c = h.db()
    with Tx(c):
        if folder_count(c, user["id"]) >= MAX_FOLDERS:
            raise bad("too_many_folders", MAX_FOLDERS)
        if folder_row(c, user["id"], fid):
            raise ApiError(409, "folder_exists")
        insert_folder(c, user["id"], fid, name, items, bool(body.get("exclude")))
        r = folder_row(c, user["id"], fid)
    return 201, {"folder": folder_json(r, [])}


def api_folder_update(h, user, body, fid):
    if not isinstance(body, dict):
        raise bad("invalid_body")
    sets, vals = [], []
    if "name" in body:
        sets.append("name=?"); vals.append(clean_name(body["name"]))
    if "items" in body:
        sets.append("items=?"); vals.append(json.dumps(clean_items(body["items"]), ensure_ascii=False))
    if "exclude" in body:
        if not isinstance(body["exclude"], bool):
            raise bad("invalid_exclude")
        sets.append("exclude=?"); vals.append(1 if body["exclude"] else 0)
    if not sets:
        raise bad("nothing_to_update")
    c = h.db()
    with Tx(c):
        cur = c.execute("UPDATE folders SET " + ", ".join(sets) + ", updated=? WHERE user_id=? AND id=?",
                        (*vals, now_ms(), user["id"], fid))
        if cur.rowcount == 0:
            raise ApiError(404, "folder_not_found")
        r = folder_row(c, user["id"], fid)
    return 200, {"folder": folder_json(r)}


def api_folder_delete(h, user, body, fid):
    c = h.db()
    with Tx(c):
        c.execute("DELETE FROM spins WHERE user_id=? AND folder_id=?", (user["id"], fid))
        if c.execute("DELETE FROM folders WHERE user_id=? AND id=?", (user["id"], fid)).rowcount == 0:
            raise ApiError(404, "folder_not_found")
    return 200, {"ok": True}


def api_folders_order(h, user, body):
    ids = body.get("ids") if isinstance(body, dict) else None
    if not isinstance(ids, list) or len(ids) > MAX_FOLDERS or not all(isinstance(i, str) and ID_RE.match(i) for i in ids):
        raise bad("invalid_ids")
    c = h.db()
    with Tx(c):
        for pos, fid in enumerate(ids):
            c.execute("UPDATE folders SET position=? WHERE user_id=? AND id=?", (pos, user["id"], fid))
        # folders not listed keep their relative order after the listed ones
        rest = c.execute("SELECT id FROM folders WHERE user_id=? ORDER BY position, created", (user["id"],)).fetchall()
        extra = [r["id"] for r in rest if r["id"] not in set(ids)]
        for k, fid in enumerate(extra):
            c.execute("UPDATE folders SET position=? WHERE user_id=? AND id=?", (len(ids) + k, user["id"], fid))
    return 200, {"ok": True}


def api_spin_add(h, user, body, fid):
    if not isinstance(body, dict):
        raise bad("invalid_body")
    item = clean_item(body.get("item"))
    if not item:
        raise bad("invalid_item")
    n = body.get("n", 0)
    if isinstance(n, bool) or not isinstance(n, int) or not 0 <= n <= MAX_ITEMS:
        raise bad("invalid_n")
    t = now_ms()
    c = h.db()
    with Tx(c):
        if not folder_row(c, user["id"], fid):
            raise ApiError(404, "folder_not_found")
        c.execute("INSERT INTO spins(user_id,folder_id,item,set_size,ts) VALUES(?,?,?,?,?)", (user["id"], fid, item, n, t))
        trim_history(c, user["id"], fid)
    return 201, {"spin": {"t": t, "w": item, "n": n}}


def api_spins_clear(h, user, body, fid):
    c = h.db()
    with Tx(c):
        if not folder_row(c, user["id"], fid):
            raise ApiError(404, "folder_not_found")
        c.execute("DELETE FROM spins WHERE user_id=? AND folder_id=?", (user["id"], fid))
    return 200, {"ok": True}


def api_export(h, user, body):
    data = {"app": "roulette", "version": 2,
            "exportedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "folders": load_state(h.db(), user["id"])}
    h.extra_headers.append(("Content-Disposition", 'attachment; filename="roulette-%s.json"' % time.strftime("%Y%m%d")))
    return 200, data


def api_import(h, user, body):
    if not isinstance(body, dict) or body.get("mode") not in ("merge", "replace"):
        raise bad("invalid_mode")
    folders = normalize_import(body.get("data"))
    uid = user["id"]
    added = merged = skipped = 0
    c = h.db()
    with Tx(c):
        if body["mode"] == "replace":
            c.execute("DELETE FROM spins WHERE user_id=?", (uid,))
            c.execute("DELETE FROM folders WHERE user_id=?", (uid,))
        for f in folders:
            ex = folder_row(c, uid, f["id"])
            if ex:
                seen = {(r["ts"], r["item"]) for r in c.execute(
                    "SELECT ts, item FROM spins WHERE user_id=? AND folder_id=?", (uid, f["id"]))}
                new = [e for e in f["history"] if (e[0], e[1]) not in seen]
                c.executemany("INSERT INTO spins(user_id,folder_id,item,set_size,ts) VALUES(?,?,?,?,?)",
                              [(uid, f["id"], w, n, t) for t, w, n in new])
                if not json.loads(ex["items"]) and f["items"]:
                    c.execute("UPDATE folders SET items=?, updated=? WHERE user_id=? AND id=?",
                              (json.dumps(f["items"], ensure_ascii=False), now_ms(), uid, f["id"]))
                trim_history(c, uid, f["id"])
                merged += 1
                continue
            if folder_count(c, uid) >= MAX_FOLDERS:
                skipped += 1
                continue
            insert_folder(c, uid, f["id"], f["name"], f["items"], f["exclude"], f["created"])
            c.executemany("INSERT INTO spins(user_id,folder_id,item,set_size,ts) VALUES(?,?,?,?,?)",
                          [(uid, f["id"], w, n, t) for t, w, n in f["history"]])
            added += 1
    return 200, {"added": added, "merged": merged, "skipped": skipped, "folders": load_state(c, uid)}


FID = r"([A-Za-z0-9_-]{1,40})"
ROUTES = [
    # method, path regex, handler, auth required, max body
    ("GET", r"/api/config", api_config, False, 0),
    ("GET", r"/api/me", api_me, False, 0),
    ("POST", r"/api/auth/google", api_login, False, 16 * 1024),
    ("POST", r"/api/auth/logout", api_logout, False, 1024),
    ("GET", r"/api/state", api_state, True, 0),
    ("GET", r"/api/export", api_export, True, 0),
    ("POST", r"/api/import", api_import, True, MAX_IMPORT_BODY),
    ("POST", r"/api/folders", api_folder_create, True, MAX_BODY),
    ("PUT", r"/api/folders/order", api_folders_order, True, MAX_BODY),
    ("PATCH", r"/api/folders/" + FID, api_folder_update, True, MAX_BODY),
    ("DELETE", r"/api/folders/" + FID, api_folder_delete, True, 0),
    ("POST", r"/api/folders/" + FID + r"/spins", api_spin_add, True, 4096),
    ("DELETE", r"/api/folders/" + FID + r"/spins", api_spins_clear, True, 0),
]
ROUTES = [(m, re.compile("^" + p + "$"), fn, auth, mb) for m, p, fn, auth, mb in ROUTES]

CSP = "; ".join([
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' https://accounts.google.com/gsi/client https://static.cloudflareinsights.com",
    "style-src 'self' 'unsafe-inline' https://accounts.google.com/gsi/style",
    "frame-src https://accounts.google.com/gsi/ https://accounts.google.com/",
    "connect-src 'self' https://accounts.google.com/gsi/ https://cloudflareinsights.com",
    "img-src 'self' data: https://*.googleusercontent.com https://*.gstatic.com",
    "font-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
])
SECURITY_HEADERS = [
    ("Content-Security-Policy", CSP),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "strict-origin-when-cross-origin"),
    ("X-Frame-Options", "DENY"),
    ("Cross-Origin-Opener-Policy", "same-origin-allow-popups"),
    ("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()"),
]


class Handler(BaseHTTPRequestHandler):
    server_version = "roulette"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    # ---- helpers
    def setup(self):
        super().setup()
        self._db = None
        self.extra_headers = []

    def db(self):
        if self._db is None:
            self._db = connect()
        return self._db

    def client_ip(self):
        return self.headers.get("CF-Connecting-IP") or self.client_address[0]

    def log_message(self, fmt, *args):
        log.info("%s %s", self.client_ip(), fmt % args)

    def session_token(self):
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        try:
            jar = cookies.SimpleCookie()
            jar.load(raw)
        except cookies.CookieError:
            return None
        m = jar.get(SESSION_COOKIE)
        return m.value if m and re.fullmatch(r"[A-Za-z0-9_-]{20,100}", m.value) else None

    def current_user(self):
        token = self.session_token()
        if not token:
            return None
        sid = hashlib.sha256(token.encode()).hexdigest()
        t = now_ms()
        c = self.db()
        r = c.execute("""SELECT u.*, s.last_seen AS s_last FROM sessions s JOIN users u ON u.id = s.user_id
                         WHERE s.id=? AND s.expires > ?""", (sid, t)).fetchone()
        if r and (r["s_last"] or 0) < t - 3600 * 1000:
            c.execute("UPDATE sessions SET last_seen=? WHERE id=?", (t, sid))
        return r

    def set_cookie(self, value, max_age):
        self.extra_headers.append(("Set-Cookie", "%s=%s; Path=/; Max-Age=%d; HttpOnly; Secure; SameSite=Lax"
                                   % (SESSION_COOKIE, value, max_age)))

    def send(self, status, body, ctype, cache="no-store", head=False):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", cache)
        for k, v in SECURITY_HEADERS + self.extra_headers:
            self.send_header(k, v)
        self.end_headers()
        if not head:
            self.wfile.write(body)

    def send_json(self, status, obj):
        self.send(status, json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8"),
                  "application/json; charset=utf-8")

    def same_origin_ok(self):
        """CSRF defence for state-changing requests: custom header + Origin/Sec-Fetch-Site checks."""
        if self.headers.get("X-Requested-With") != "roulette":
            return False
        origin = self.headers.get("Origin")
        host = self.headers.get("Host", "")
        if origin:
            o = urlsplit(origin)
            if o.netloc != host or o.scheme not in ("https", "http"):
                return False
            if o.scheme == "http" and o.hostname not in ("127.0.0.1", "localhost"):
                return False
        sfs = self.headers.get("Sec-Fetch-Site")
        if sfs and sfs not in ("same-origin", "none"):
            return False
        return True

    def read_json(self, limit):
        length = self.headers.get("Content-Length")
        if self.headers.get("Transfer-Encoding"):
            raise ApiError(411, "length_required")
        n = int(length) if length and length.isdigit() else 0
        if n > limit:
            raise ApiError(413, "body_too_large")
        if n == 0:
            return {}
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if ctype != "application/json":
            raise ApiError(415, "json_required")
        raw = self.rfile.read(n)
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            raise bad("invalid_json")

    # ---- dispatch
    def handle_any(self, method):
        path = urlsplit(self.path).path
        try:
            if not path.startswith("/api/"):
                if method not in ("GET", "HEAD"):
                    raise ApiError(405, "method_not_allowed")
                return self.serve_static(path, head=method == "HEAD")
            for m, rx, fn, auth, maxb in ROUTES:
                mt = rx.match(path)
                if not mt or m != method:
                    continue
                if method != "GET" and not self.same_origin_ok():
                    raise ApiError(403, "csrf_check_failed")
                body = self.read_json(maxb) if method in ("POST", "PUT", "PATCH") else None
                user = self.current_user() if auth or fn is api_me else None
                if auth and not user:
                    raise ApiError(401, "unauthorized")
                status, obj = fn(self, user, body, *mt.groups())
                return self.send_json(status, obj)
            if any(rx.match(path) for _, rx, *_ in ROUTES):
                raise ApiError(405, "method_not_allowed")
            raise ApiError(404, "not_found")
        except ApiError as e:
            if e.status >= 400 and method in ("POST", "PUT", "PATCH") and self.headers.get("Content-Length", "0").isdigit():
                self.close_connection = True  # unread body might remain
            out = {"error": e.code}
            if e.detail is not None:
                out["detail"] = e.detail
            self.send_json(e.status, out)
        except Exception:
            log.exception("unhandled error on %s %s", method, path)
            self.close_connection = True
            self.send_json(500, {"error": "internal"})
        finally:
            if self._db is not None:
                self._db.close()
                self._db = None

    def serve_static(self, path, head=False):
        name = STATIC_FILES.get(path)
        if not name:
            return self.send(404, b"Not found", "text/plain; charset=utf-8", head=head)
        with open(os.path.join(ROOT, name), "rb") as f:
            body = f.read()
        self.send(200, body, "text/html; charset=utf-8", cache="no-cache", head=head)

    def do_GET(self):
        self.handle_any("GET")

    def do_HEAD(self):
        self.handle_any("HEAD")

    def do_POST(self):
        self.handle_any("POST")

    def do_PUT(self):
        self.handle_any("PUT")

    def do_PATCH(self):
        self.handle_any("PATCH")

    def do_DELETE(self):
        self.handle_any("DELETE")


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def make_server(host=HOST, port=PORT):
    init_db()
    return Server((host, port), Handler)


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", stream=sys.stderr)
    srv = make_server()
    cid = config()["google_client_id"]
    log.info("roulette listening on http://%s:%d (google login %s)", HOST, PORT, "enabled" if cid else "NOT configured")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
