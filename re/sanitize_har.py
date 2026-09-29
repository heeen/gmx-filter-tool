#!/usr/bin/env python3
"""Reduce a browser HAR export to a secret-free JSON trace of API calls.

Run this yourself on the raw HAR; only hand over the output file.

    python3 re/sanitize_har.py raw.har re/webmail-trace.json

The script prompts (no echo) for your password and email address so it can
scrub them - plus URL-encoded and base64 variants - from everything it keeps.
Leave the prompts empty to skip. It prints only counts, never content.

Allowlist approach: only a handful of headers survive; cookies, auth headers,
login/token request bodies and static assets are dropped entirely. Token-like
strings (long high-entropy runs, sid/session params) are replaced with salted
hash placeholders, so the same token maps to the same placeholder within one
run (lets us correlate ids) but cannot be reversed.
"""

import base64
import getpass
import hashlib
import json
import os
import re
import sys
from urllib.parse import parse_qsl, quote, quote_plus, urlencode, urlsplit, urlunsplit

KEEP_HEADERS = {"content-type", "accept", "x-requested-with", "x-ui-app", "origin"}
SECRET_KEY = re.compile(r"pass|pwd|token|secret|session|sid|cookie|auth|otp|ticket|nonce|csrf", re.I)
# Long runs of token alphabet; real mail content (addresses, subjects) rarely matches.
TOKEN_LIKE = re.compile(r"[A-Za-z0-9_\-+/=.%]{32,}")
# Within URL paths redact per segment, so ids stay distinguishable from route names.
PATH_TOKEN_LIKE = re.compile(r"[A-Za-z0-9_\-+=.%]{32,}")
# Non-secret protocol fields worth keeping on auth endpoints (values are enums/ids, not credentials).
AUTH_PUBLIC_KEYS = {"grant_type", "scope", "client_id", "response_type", "token_type", "expires_in", "redirect_uri", "service", "error", "error_description"}
SESSION_IN_URL = re.compile(r"((?:;jsessionid|[?&;]sid|[?&;]session\w*)=)[^&;#/]+", re.I)
SENSITIVE_PATH = re.compile(r"login|logon|signin|oauth|token|auth|sso|session", re.I)
STATIC_ASSET = re.compile(r"\.(js|mjs|css|png|jpe?g|gif|svg|ico|woff2?|ttf|map|webp)(\?|$)", re.I)
TEXT_MIME = re.compile(r"json|xml|text/plain|javascript|html", re.I)

SALT = os.urandom(16)


def placeholder(value: str) -> str:
    return "<redacted:" + hashlib.sha256(SALT + value.encode()).hexdigest()[:8] + ">"


class Scrubber:
    def __init__(self, literals: list[str]):
        variants = set()
        for lit in filter(None, literals):
            variants |= {lit, quote(lit, safe=""), quote_plus(lit), base64.b64encode(lit.encode()).decode()}
        # Longest first so a variant containing another is replaced whole.
        self.literals = sorted(variants, key=len, reverse=True)
        self.literal_hits = 0

    def literal_scrub(self, s: str) -> str:
        for lit in self.literals:
            if lit in s:
                self.literal_hits += s.count(lit)
                s = s.replace(lit, "<scrubbed>")
        return s

    def text(self, s: str) -> str:
        s = self.literal_scrub(s)
        s = SESSION_IN_URL.sub(lambda m: m.group(1) + placeholder(m.group(0)), s)
        return TOKEN_LIKE.sub(lambda m: placeholder(m.group(0)), s)

    def json_value(self, v, key: str = ""):
        if isinstance(v, dict):
            return {k: self.json_value(x, k) for k, x in v.items()}
        if isinstance(v, list):
            return [self.json_value(x, key) for x in v]
        if isinstance(v, str):
            return placeholder(v) if SECRET_KEY.search(key) else self.text(v)
        return v

    def url(self, raw: str) -> str:
        parts = urlsplit(raw)
        query = [(k, placeholder(v) if SECRET_KEY.search(k) else self.text(v)) for k, v in parse_qsl(parts.query, keep_blank_values=True)]
        path = SESSION_IN_URL.sub(lambda m: m.group(1) + placeholder(m.group(0)), parts.path)
        path = PATH_TOKEN_LIKE.sub(lambda m: placeholder(m.group(0)), self.literal_scrub(path))
        return urlunsplit((parts.scheme, parts.netloc, path, urlencode(query, safe="<>:"), ""))

    def auth_body(self, text: str | None, mime: str):
        """Keep keys and a few protocol fields of auth traffic; every other value is dropped."""
        if not text:
            return None
        if "json" in mime:
            try:
                data = json.loads(text)
            except ValueError:
                return "<dropped: auth-related endpoint>"
            if isinstance(data, dict):
                return {k: v if k in AUTH_PUBLIC_KEYS and not isinstance(v, (dict, list)) else "<dropped>" for k, v in data.items()}
        if "x-www-form-urlencoded" in mime:
            return {k: v if k in AUTH_PUBLIC_KEYS else "<dropped>" for k, v in parse_qsl(text, keep_blank_values=True)}
        return "<dropped: auth-related endpoint>"

    def body(self, text: str | None, mime: str):
        if not text:
            return None
        if "json" in mime:
            try:
                return self.json_value(json.loads(text))
            except ValueError:
                pass
        if "x-www-form-urlencoded" in mime:
            return {k: placeholder(v) if SECRET_KEY.search(k) else self.text(v) for k, v in parse_qsl(text, keep_blank_values=True)}
        if TEXT_MIME.search(mime):
            return self.text(text)
        return f"<{len(text)} bytes of {mime or 'unknown'} dropped>"


def response_text(content: dict) -> str | None:
    text = content.get("text")
    if text and content.get("encoding") == "base64":
        try:
            return base64.b64decode(text).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return None
    return text


def sanitize_entry(entry: dict, s: Scrubber) -> dict | None:
    req, resp = entry["request"], entry["response"]
    url = req["url"]
    if STATIC_ASSET.search(urlsplit(url).path) or not url.startswith("http"):
        return None
    sensitive = bool(SENSITIVE_PATH.search(urlsplit(url).path) or SENSITIVE_PATH.search(urlsplit(url).netloc))

    def headers(hs):
        kept = {h["name"].lower(): s.text(h["value"]) for h in hs if h["name"].lower() in KEEP_HEADERS}
        for h in hs:
            if h["name"].lower() == "authorization":
                kept["authorization"] = h["value"].split(" ", 1)[0] + " <dropped>"
        return kept

    post = req.get("postData") or {}
    post_mime = post.get("mimeType", "")
    resp_mime = resp.get("content", {}).get("mimeType", "")
    return {
        "method": req["method"],
        "url": s.url(url),
        "request_headers": headers(req.get("headers", [])),
        "request_body": s.auth_body(post.get("text"), post_mime) if sensitive else s.body(post.get("text"), post_mime),
        "status": resp.get("status"),
        "response_headers": headers(resp.get("headers", [])),
        "response_body": s.auth_body(response_text(resp.get("content", {})), resp_mime) if sensitive else s.body(response_text(resp.get("content", {})), resp_mime),
    }


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit(f"usage: {sys.argv[0]} <raw.har> <out.json>")
    src, dst = sys.argv[1:]
    password = getpass.getpass("GMX password to scrub (empty to skip): ")
    email = getpass.getpass("GMX email address to scrub (empty to skip): ")
    literals = [password, email]
    if email and "@" in email:
        literals.append(email.split("@", 1)[0])
    scrubber = Scrubber(literals)

    with open(src, encoding="utf-8") as f:
        har = json.load(f)
    entries = har["log"]["entries"]
    kept = [e for e in (sanitize_entry(x, scrubber) for x in entries) if e is not None]

    with open(dst, "w", encoding="utf-8") as f:
        json.dump(kept, f, indent=2, ensure_ascii=False)

    if password:
        with open(dst, encoding="utf-8") as f:
            if password in f.read():
                os.remove(dst)
                sys.exit("password still present in output - deleted it, please report this")
    print(f"kept {len(kept)} of {len(entries)} requests, scrubbed {scrubber.literal_hits} password/email occurrences -> {dst}")


if __name__ == "__main__":
    main()
