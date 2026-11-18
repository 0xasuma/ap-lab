#!/usr/bin/env python3
"""Signed ActivityPub delivery to a target inbox (draft-cavage HTTP Signatures).

Usage:
  ap_sign.py <path> <actor_url> <json_body_file>
Prints status + body so the caller can assert on it.
"""
import sys, json, base64, hashlib, time, datetime, http.client, ssl

KEY = "/root/r421/ap/lab.pem"
HOST = "try.nodebb.org"


def sign_headers(path, actor_url, body_bytes):
    digest = "SHA-256=" + base64.b64encode(hashlib.sha256(body_bytes).digest()).decode()
    date = datetime.datetime.now(datetime.timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
    key_id = actor_url + "#main-key"
    headers = f"(request-target) host date digest"
    signing_string = (
        f"(request-target): post {path}\n"
        f"host: {HOST}\n"
        f"date: {date}\n"
        f"digest: {digest}"
    )
    with open(KEY, "rb") as f:
        key_pem = f.read()
    # sign with openssl (RSA-SHA256)
    import subprocess
    p = subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", KEY],
        input=signing_string.encode(), capture_output=True,
    )
    if p.returncode != 0:
        raise SystemExit("openssl sign failed: " + p.stderr.decode()[:200])
    sig = base64.b64encode(p.stdout).decode()
    return {
        "Host": HOST,
        "Date": date,
        "Digest": digest,
        "Signature": (
            f'keyId="{key_id}",algorithm="rsa-sha256",'
            f'headers="{headers}",signature="{sig}"'
        ),
        "Content-Type": "application/activity+json",
        "Accept": "application/activity+json",
    }


def main():
    path = sys.argv[1]
    actor_url = sys.argv[2]
    body = open(sys.argv[3], "rb").read()
    hdrs = sign_headers(path, actor_url, body)
    ctx = ssl.create_default_context()
    conn = http.client.HTTPSConnection(HOST, 443, context=ctx, timeout=25)
    conn.request("POST", path, body=body, headers=hdrs)
    r = conn.getresponse()
    data = r.read().decode("utf-8", "replace")
    print(json.dumps({"status": r.status, "path": path, "actor": actor_url,
                      "body": data[:300], "headers": dict(r.getheaders()).get("set-cookie", "")[:0]}))


if __name__ == "__main__":
    main()
