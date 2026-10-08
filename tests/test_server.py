"""Tests for server.py. Run: python3 -m unittest discover -s tests -v

Uses a locally generated RSA key and a test-only key lookup injected via
monkeypatching inside this process; the production server has no bypass.
"""
import base64
import hashlib
import json
import os
import random
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

TMP = tempfile.mkdtemp(prefix="roulette-test-")
CLIENT_ID = "1234567890-testclient.apps.googleusercontent.com"
os.environ["ROULETTE_DATA_DIR"] = TMP
os.environ["ROULETTE_CONFIG"] = os.path.join(TMP, "config.local.json")
with open(os.environ["ROULETTE_CONFIG"], "w") as f:
    json.dump({"google_client_id": CLIENT_ID}, f)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import server  # noqa: E402


# ---------- tiny RSA for tests ----------
def _is_prime(n, rounds=24):
    if n < 4:
        return n in (2, 3)
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29):
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2; s += 1
    rng = random.SystemRandom()
    for _ in range(rounds):
        x = pow(rng.randrange(2, n - 1), d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _prime(bits):
    rng = random.SystemRandom()
    while True:
        c = rng.getrandbits(bits) | (1 << (bits - 1)) | (1 << (bits - 2)) | 1
        if _is_prime(c):
            return c


def gen_rsa(bits=2048):
    e = 65537
    while True:
        p, q = _prime(bits // 2), _prime(bits // 2)
        phi = (p - 1) * (q - 1)
        if p != q and phi % e and (p * q).bit_length() == bits:
            return p * q, e, pow(e, -1, phi)


def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def sign(n, d, header, claims):
    h = b64(json.dumps(header).encode()) + "." + b64(json.dumps(claims).encode())
    k = (n.bit_length() + 7) // 8
    t = server._SHA256_DIGEST_INFO + hashlib.sha256(h.encode()).digest()
    em = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    s = pow(int.from_bytes(em, "big"), d, n).to_bytes(k, "big")
    return h + "." + b64(s)


N, E, D = gen_rsa()
N2, E2, D2 = gen_rsa()
KID = "test-kid"
KEYS = {KID: (N, E)}


def claims(**kw):
    t = int(time.time())
    c = {"iss": "https://accounts.google.com", "aud": CLIENT_ID, "sub": "1001", "email": "a@example.com",
         "name": "테스트 A", "picture": "https://lh3.googleusercontent.com/a", "iat": t, "exp": t + 3600}
    c.update(kw)
    return c


def token(c=None, kid=KID, d=D, n=N, alg="RS256"):
    return sign(n, d, {"alg": alg, "kid": kid, "typ": "JWT"}, c or claims())


class TokenTests(unittest.TestCase):
    def v(self, tok):
        return server.verify_google_id_token(tok, CLIENT_ID, key_lookup=KEYS.get)

    def test_valid(self):
        self.assertEqual(self.v(token())["sub"], "1001")

    def test_rejections(self):
        good = token()
        h, p, s = good.split(".")
        forged_payload = b64(json.dumps(claims(sub="attacker")).encode())
        cases = {
            "tampered payload": h + "." + forged_payload + "." + s,
            "wrong key": token(d=D2, n=N),
            "signed by other key": token(n=N2, d=D2),
            "unknown kid": token(kid="nope"),
            "alg none": b64(b'{"alg":"none","kid":"test-kid"}') + "." + p + ".",
            "alg HS256": token(alg="HS256"),
            "bad aud": token(claims(aud="other.apps.googleusercontent.com")),
            "bad iss": token(claims(iss="https://evil.example")),
            "expired": token(claims(exp=int(time.time()) - 3600)),
            "future iat": token(claims(iat=int(time.time()) + 3600)),
            "no sub": token(claims(sub="")),
            "garbage": "abc.def",
            "not str": None,
            "truncated sig": h + "." + p + "." + s[:-10],
        }
        for name, tok in cases.items():
            with self.subTest(name):
                with self.assertRaises(server.TokenError):
                    self.v(tok)

    def test_real_google_jwks_rejects_forged(self):
        # Real network path: forged token claiming a Google kid must fail (unknown kid or bad signature).
        try:
            server._fetch_google_jwks()
        except Exception as e:  # pragma: no cover
            self.skipTest("no network: %s" % e)
        real_kid = next(iter(server._fetch_google_jwks()[0]))
        for kid in (real_kid, "forged-kid"):
            with self.assertRaises(server.TokenError):
                server.verify_google_id_token(token(kid=kid), CLIENT_ID)


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._orig = server.google_key
        server.google_key = KEYS.get  # test-only key lookup, this process only
        cls.srv = server.make_server("127.0.0.1", 0)
        cls.base = "http://127.0.0.1:%d" % cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        server.google_key = cls._orig

    def req(self, method, path, body=None, cookie=None, headers=None, raw=None):
        h = {"X-Requested-With": "roulette"}
        if headers is not None:
            h = headers
        data = None
        if raw is not None:
            data = raw
            h.setdefault("Content-Type", "application/json")
        elif body is not None:
            data = json.dumps(body).encode()
            h["Content-Type"] = "application/json"
        if cookie:
            h["Cookie"] = cookie
        r = urllib.request.Request(self.base + path, data=data, method=method, headers=h)
        try:
            with urllib.request.urlopen(r) as resp:
                return resp.status, json.loads(resp.read() or b"null"), resp.headers
        except urllib.error.HTTPError as e:
            txt = e.read()
            try:
                return e.code, json.loads(txt), e.headers
            except Exception:
                return e.code, txt, e.headers

    def login(self, sub="1001", email="a@example.com"):
        st, js, hd = self.req("POST", "/api/auth/google", {"credential": token(claims(sub=sub, email=email))})
        self.assertEqual(st, 200, js)
        sc = hd.get("Set-Cookie")
        for attr in ("HttpOnly", "Secure", "SameSite=Lax", "Path=/", "Max-Age=7776000"):
            self.assertIn(attr, sc)
        self.assertTrue(sc.startswith("__Host-roulette_sid="))
        return sc.split(";")[0]

    def test_static_and_headers(self):
        with urllib.request.urlopen(self.base + "/") as r:
            self.assertEqual(r.status, 200)
            self.assertIn("frame-ancestors 'none'", r.headers["Content-Security-Policy"])
            self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")
        for p in ("/server.py", "/config.local.json", "/data/roulette.db", "/.git/config", "/../server.py"):
            st, _, _ = self.req("GET", p)
            self.assertEqual(st, 404, p)

    def test_config_and_unauth(self):
        st, js, _ = self.req("GET", "/api/config")
        self.assertEqual((st, js["login_enabled"], js["google_client_id"]), (200, True, CLIENT_ID))
        st, js, _ = self.req("GET", "/api/me")
        self.assertEqual((st, js["user"]), (200, None))
        for m, p in (("GET", "/api/state"), ("GET", "/api/export"), ("POST", "/api/folders"),
                     ("PATCH", "/api/folders/abc"), ("DELETE", "/api/folders/abc"), ("POST", "/api/folders/abc/spins")):
            st, js, _ = self.req(m, p, {} if m in ("POST", "PATCH") else None)
            self.assertEqual(st, 401, (m, p, js))
        st, js, _ = self.req("GET", "/api/state", cookie="__Host-roulette_sid=" + "x" * 43)
        self.assertEqual(st, 401)

    def test_bad_login(self):
        st, js, hd = self.req("POST", "/api/auth/google", {"credential": token(claims(aud="x.apps.googleusercontent.com"))})
        self.assertEqual((st, js["error"]), (401, "invalid_token"))
        self.assertIsNone(hd.get("Set-Cookie"))
        st, js, _ = self.req("POST", "/api/auth/google", {"credential": token(d=D2)})
        self.assertEqual(st, 401)

    def test_csrf(self):
        ck = self.login()
        st, js, _ = self.req("POST", "/api/folders", {"name": "x"}, cookie=ck, headers={})
        self.assertEqual((st, js["error"]), (403, "csrf_check_failed"))
        st, js, _ = self.req("POST", "/api/folders", {"name": "x"}, cookie=ck,
                             headers={"X-Requested-With": "roulette", "Origin": "https://evil.example"})
        self.assertEqual(st, 403)
        st, js, _ = self.req("POST", "/api/folders", {"name": "x"}, cookie=ck,
                             headers={"X-Requested-With": "roulette", "Sec-Fetch-Site": "cross-site"})
        self.assertEqual(st, 403)
        st, js, _ = self.req("POST", "/api/auth/google", {"credential": token()}, headers={})
        self.assertEqual(st, 403)

    def test_full_flow_and_scoping(self):
        a = self.login("2001", "a@x.com")
        b = self.login("2002", "b@x.com")
        st, js, _ = self.req("GET", "/api/me", cookie=a)
        self.assertEqual(js["user"]["email"], "a@x.com")
        st, js, _ = self.req("POST", "/api/folders", {"id": "lunch1", "name": " 점심 ", "items": ["김치찌개", "돈까스", "쌀국수"]}, cookie=a)
        self.assertEqual(st, 201, js)
        self.assertEqual(js["folder"]["name"], "점심")
        st, js, _ = self.req("POST", "/api/folders", {"id": "lunch1", "name": "dup"}, cookie=a)
        self.assertEqual(st, 409)
        self.req("POST", "/api/folders", {"id": "walk1", "name": "산책", "items": ["한강", "공원"]}, cookie=a)
        st, js, _ = self.req("POST", "/api/folders/lunch1/spins", {"item": "돈까스", "n": 3}, cookie=a)
        self.assertEqual(st, 201)
        self.assertLessEqual(abs(js["spin"]["t"] - time.time() * 1000), 5000)
        st, js, _ = self.req("PATCH", "/api/folders/lunch1", {"name": "점심메뉴", "items": ["a", "b"], "exclude": True}, cookie=a)
        self.assertEqual((st, js["folder"]["exclude"], js["folder"]["items"]), (200, True, ["a", "b"]))
        st, js, _ = self.req("PUT", "/api/folders/order", {"ids": ["walk1", "lunch1"]}, cookie=a)
        st, js, _ = self.req("GET", "/api/state", cookie=a)
        self.assertEqual([f["id"] for f in js["folders"]], ["walk1", "lunch1"])
        self.assertEqual(js["folders"][1]["history"][0]["w"], "돈까스")
        # user B can't see or touch A's data
        st, js, _ = self.req("GET", "/api/state", cookie=b)
        self.assertEqual(js["folders"], [])
        for m, p, body in (("PATCH", "/api/folders/lunch1", {"name": "hack"}), ("DELETE", "/api/folders/lunch1", None),
                           ("POST", "/api/folders/lunch1/spins", {"item": "x", "n": 1}), ("DELETE", "/api/folders/lunch1/spins", None)):
            st, js, _ = self.req(m, p, body, cookie=b)
            self.assertEqual(st, 404, (m, p))
        # B can use the same folder id independently
        st, js, _ = self.req("POST", "/api/folders", {"id": "lunch1", "name": "B의 점심"}, cookie=b)
        self.assertEqual(st, 201)
        st, js, _ = self.req("GET", "/api/state", cookie=a)
        self.assertEqual(js["folders"][1]["name"], "점심메뉴")
        # export / import
        st, exp, hd = self.req("GET", "/api/export", cookie=a)
        self.assertIn("attachment", hd["Content-Disposition"])
        st, js, _ = self.req("POST", "/api/import", {"mode": "merge", "data": exp}, cookie=a)
        self.assertEqual((js["merged"], js["added"]), (2, 0))
        st, js, _ = self.req("GET", "/api/state", cookie=a)
        self.assertEqual(len(js["folders"][1]["history"]), 1)  # deduped
        guest = {"folders": [{"id": "g1", "name": "게스트", "items": ["x", "y"], "history": [{"t": 1759900000000, "w": "x", "n": 2}, {"t": "bad", "w": "y"}]}]}
        st, js, _ = self.req("POST", "/api/import", {"mode": "merge", "data": guest}, cookie=a)
        self.assertEqual(js["added"], 1)
        self.assertEqual(len([f for f in js["folders"] if f["id"] == "g1"][0]["history"]), 1)
        st, js, _ = self.req("POST", "/api/import", {"mode": "replace", "data": guest}, cookie=b)
        self.assertEqual([f["id"] for f in js["folders"]], ["g1"])
        # clear + delete
        st, js, _ = self.req("DELETE", "/api/folders/lunch1/spins", cookie=a)
        st, js, _ = self.req("DELETE", "/api/folders/walk1", cookie=a)
        st, js, _ = self.req("GET", "/api/state", cookie=a)
        self.assertEqual([(f["id"], len(f["history"])) for f in js["folders"]], [("lunch1", 0), ("g1", 1)])
        # logout invalidates session
        st, js, hd = self.req("POST", "/api/auth/logout", cookie=a)
        self.assertIn("Max-Age=0", hd["Set-Cookie"])
        st, js, _ = self.req("GET", "/api/state", cookie=a)
        self.assertEqual(st, 401)

    def test_validation(self):
        a = self.login("3001")
        cases = [
            ({"name": ""}, "invalid_name"),
            ({"name": "x", "items": ["i"] * 51}, "too_many_items"),
            ({"name": "x", "items": ["a" * 101]}, "item_too_long"),
            ({"name": "x", "items": "notalist"}, "invalid_items"),
            ({"id": "../etc", "name": "x"}, "invalid_id"),
            ({"name": 5}, "invalid_name"),
        ]
        for body, err in cases:
            st, js, _ = self.req("POST", "/api/folders", body, cookie=a)
            self.assertEqual((st, js["error"]), (400, err), body)
        st, js, _ = self.req("POST", "/api/folders", raw=b"{not json", cookie=a)
        self.assertEqual(st, 400)
        st, js, _ = self.req("POST", "/api/folders", raw=b"x" * (70 * 1024), cookie=a)
        self.assertEqual(st, 413)
        st, js, _ = self.req("POST", "/api/folders", raw=b'{"name":"x"}', cookie=a,
                             headers={"X-Requested-With": "roulette", "Content-Type": "text/plain"})
        self.assertEqual(st, 415)
        for i in range(server.MAX_FOLDERS):
            st, js, _ = self.req("POST", "/api/folders", {"name": "f%d" % i}, cookie=a)
            self.assertEqual(st, 201)
        st, js, _ = self.req("POST", "/api/folders", {"name": "one too many"}, cookie=a)
        self.assertEqual((st, js["error"]), (400, "too_many_folders"))
        fid = js and self.req("GET", "/api/state", cookie=a)[1]["folders"][0]["id"]
        st, js, _ = self.req("POST", "/api/folders/%s/spins" % fid, {"item": "x", "n": 99}, cookie=a)
        self.assertEqual(st, 400)

    def test_history_cap(self):
        a = self.login("4001")
        self.req("POST", "/api/folders", {"id": "cap", "name": "cap", "items": ["a", "b"]}, cookie=a)
        old = server.MAX_HISTORY
        server.MAX_HISTORY = 5
        try:
            for _ in range(8):
                self.req("POST", "/api/folders/cap/spins", {"item": "a", "n": 2}, cookie=a)
        finally:
            server.MAX_HISTORY = old
        st, js, _ = self.req("GET", "/api/state", cookie=a)
        self.assertEqual(len(js["folders"][0]["history"]), 5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
