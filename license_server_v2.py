# -*- coding: utf-8 -*-
"""
License server (Railway compatible).

MANTIK DEĞİŞMEDİ:
- license_db.json server-side only
- first activation binds key -> HWID and marks used
- returns signed activation payload (RSA-PSS SHA256)
- /public_key and /activate endpoints stay the same
"""
import base64
import json
import os
import time
from pathlib import Path
from flask import Flask, request, jsonify

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


# Gunicorn/Railway için standart isim: app
app = Flask(__name__)

# Railway'de kalıcı disk (Volume) bağlarsan DATA_DIR=/app/data yapacağız.
# Volume yoksa local "./data" altında çalışır.
DATA_DIR = Path(os.getenv("DATA_DIR", "./data")).resolve()
DATA_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = DATA_DIR / "license_db.json"
PRIVATE_KEY_PATH = DATA_DIR / "private_key.pem"
PUBLIC_KEY_PATH  = DATA_DIR / "public_key.pem"


def canonical_json_bytes(obj: dict) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def load_db() -> dict:
    if not DB_PATH.exists():
        return {}
    return json.loads(DB_PATH.read_text(encoding="utf-8"))


def save_db(db: dict) -> None:
    DB_PATH.write_text(json.dumps(db, ensure_ascii=False, indent=2), encoding="utf-8")


def ensure_keys():
    if PRIVATE_KEY_PATH.exists() and PUBLIC_KEY_PATH.exists():
        return
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    PRIVATE_KEY_PATH.write_bytes(priv_pem)
    PUBLIC_KEY_PATH.write_bytes(pub_pem)


def load_private_key():
    ensure_keys()
    return serialization.load_pem_private_key(PRIVATE_KEY_PATH.read_bytes(), password=None)


def sign_payload(payload: dict) -> str:
    key = load_private_key()
    msg = canonical_json_bytes(payload)
    sig = key.sign(
        msg,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return base64.b64encode(sig).decode("ascii")


def normalize_key(k: str) -> str:
    k = k.strip().upper()
    # allow underscore in input, normalize to dash
    k = k.replace("_", "-")
    return k


@app.get("/public_key")
def public_key():
    ensure_keys()
    return (PUBLIC_KEY_PATH.read_text(encoding="utf-8"), 200, {"Content-Type": "text/plain; charset=utf-8"})


@app.post("/activate")
def activate():
    data = request.get_json(silent=True) or {}
    license_key = normalize_key(str(data.get("license_key", "")))
    hwid = str(data.get("hwid", "")).strip()
    if not license_key or not hwid:
        return jsonify({"ok": False, "error": "license_key ve hwid zorunlu"}), 400

    db = load_db()
    if license_key not in db:
        return jsonify({"ok": False, "error": "Geçersiz lisans"}), 403

    rec = db[license_key]
    used = bool(rec.get("used", False))
    bound_hwid = rec.get("hwid")

    if (not used) and (not bound_hwid):
        # first activation
        rec["used"] = True
        rec["hwid"] = hwid
        rec["activated_at"] = int(time.time())
        db[license_key] = rec
        save_db(db)
    else:
        # already activated: allow only same hwid
        if bound_hwid != hwid:
            return jsonify({"ok": False, "error": "Bu lisans başka bir bilgisayarda kullanılmış"}), 403

    payload = {
        "license_key": license_key,
        "hwid": hwid,
        "activated_at": db[license_key].get("activated_at", int(time.time())),
        "product": "Metin2Alert",
        "v": 1
    }
    sig = sign_payload(payload)
    return jsonify({"ok": True, "payload": payload, "sig": sig})


if __name__ == "__main__":
    ensure_keys()
    # Railway/Heroku tarzı ortamlarda PORT env kullanılır
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port)
