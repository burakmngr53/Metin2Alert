# -*- coding: utf-8 -*-
"""
License server (Render/Postgres).

MANTIK DEĞİŞMEDİ:
- İlk aktivasyon: used=true + hwid bağlanır
- Aynı key ikinci kez sadece aynı hwid ile çalışır
- /public_key ve /activate endpointleri aynıdır
EK:
- Lisanslar Postgres'te tutulur (kalıcı)
- /admin/import ile lisansları toplu yükleme (ADMIN_SIFRE ile korunur)
"""
import base64
import json
import os
import time

from flask import Flask, request, jsonify

import psycopg2
import psycopg2.extras

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


app = Flask(__name__)

DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
ADMIN_SIFRE = os.getenv("ADMIN_SIFRE", "").strip()

# ------------------------------------------------------------
# DB yardımcıları
# ------------------------------------------------------------
_db_inited = False

def db_conn():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL ayarlı değil")
    # Render/Postgres genelde SSL ister
    return psycopg2.connect(DATABASE_URL, sslmode="require")

def init_db_once():
    global _db_inited
    if _db_inited:
        return
    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS licenses (
                    license_key TEXT PRIMARY KEY,
                    used BOOLEAN NOT NULL DEFAULT FALSE,
                    hwid TEXT,
                    activated_at BIGINT
                );
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS server_keys (
                    name TEXT PRIMARY KEY,
                    pem TEXT NOT NULL
                );
            """)
    _db_inited = True

# ------------------------------------------------------------
# RSA anahtarlarını DB'de tut (sunucu restart olsa bile değişmesin)
# ------------------------------------------------------------
def ensure_keys_in_db():
    init_db_once()
    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT pem FROM server_keys WHERE name='private_key' LIMIT 1;")
            row = cur.fetchone()
            if row:
                return  # zaten var

            private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            priv_pem = private.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode("utf-8")

            pub_pem = private.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode("utf-8")

            cur.execute(
                "INSERT INTO server_keys (name, pem) VALUES (%s, %s) ON CONFLICT (name) DO NOTHING;",
                ("private_key", priv_pem),
            )
            cur.execute(
                "INSERT INTO server_keys (name, pem) VALUES (%s, %s) ON CONFLICT (name) DO NOTHING;",
                ("public_key", pub_pem),
            )

def load_private_key():
    ensure_keys_in_db()
    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT pem FROM server_keys WHERE name='private_key' LIMIT 1;")
            pem = cur.fetchone()[0]
    return serialization.load_pem_private_key(pem.encode("utf-8"), password=None)

def load_public_key_pem_text() -> str:
    ensure_keys_in_db()
    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT pem FROM server_keys WHERE name='public_key' LIMIT 1;")
            return cur.fetchone()[0]

def canonical_json_bytes(obj: dict) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")

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
    k = (k or "").strip().upper().replace("_", "-")
    return k

# ------------------------------------------------------------
# API
# ------------------------------------------------------------
@app.get("/")
def home():
    return "Metin2Alert lisans sunucusu çalışıyor.", 200

@app.get("/public_key")
def public_key():
    try:
        pem = load_public_key_pem_text()
        return (pem, 200, {"Content-Type": "text/plain; charset=utf-8"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.post("/activate")
def activate():
    init_db_once()
    data = request.get_json(silent=True) or {}
    license_key = normalize_key(str(data.get("license_key", "")))
    hwid = str(data.get("hwid", "")).strip()

    if not license_key or not hwid:
        return jsonify({"ok": False, "error": "license_key ve hwid zorunlu"}), 400

    with db_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
            # Kilitleyerek oku ki iki kişi aynı anda kullanamasın
            cur.execute(
                "SELECT license_key, used, hwid, activated_at FROM licenses WHERE license_key=%s FOR UPDATE;",
                (license_key,),
            )
            row = cur.fetchone()
            if not row:
                return jsonify({"ok": False, "error": "Geçersiz lisans"}), 403

            used = bool(row["used"])
            bound_hwid = row["hwid"]

            if (not used) and (not bound_hwid):
                # ilk aktivasyon
                activated_at = int(time.time())
                cur.execute(
                    "UPDATE licenses SET used=TRUE, hwid=%s, activated_at=%s WHERE license_key=%s;",
                    (hwid, activated_at, license_key),
                )
            else:
                # zaten aktive: sadece aynı cihaz izinli
                if bound_hwid != hwid:
                    return jsonify({"ok": False, "error": "Bu lisans başka bir bilgisayarda kullanılmış"}), 403

    payload = {
        "license_key": license_key,
        "hwid": hwid,
        "activated_at": int(time.time()),
        "product": "Metin2Alert",
        "v": 1
    }
    sig = sign_payload(payload)
    return jsonify({"ok": True, "payload": payload, "sig": sig})

# ------------------------------------------------------------
# SADECE SENİN İÇİN: lisansları toplu yükleme
# ------------------------------------------------------------
@app.post("/admin/import")
def admin_import():
    init_db_once()
    data = request.get_json(silent=True) or {}

    if not ADMIN_SIFRE:
        return jsonify({"ok": False, "error": "ADMIN_SIFRE ayarlı değil"}), 500

    sifre = str(data.get("admin_sifre", "")).strip()
    if sifre != ADMIN_SIFRE:
        return jsonify({"ok": False, "error": "Yetkisiz"}), 403

    # iki formatı destekleyelim:
    # 1) {"licenses": {"KEY1": false, "KEY2": false}}
    # 2) {"keys": ["KEY1","KEY2"]}
    licenses_dict = data.get("licenses")
    keys_list = data.get("keys")

    keys = []
    if isinstance(licenses_dict, dict):
        keys = [normalize_key(k) for k in licenses_dict.keys()]
    elif isinstance(keys_list, list):
        keys = [normalize_key(k) for k in keys_list]
    else:
        return jsonify({"ok": False, "error": "licenses veya keys göndermelisin"}), 400

    keys = [k for k in keys if k]
    if not keys:
        return jsonify({"ok": False, "error": "Boş liste"}), 400

    inserted = 0
    with db_conn() as conn:
        with conn.cursor() as cur:
            for k in keys:
                cur.execute(
                    "INSERT INTO licenses (license_key, used) VALUES (%s, FALSE) ON CONFLICT (license_key) DO NOTHING;",
                    (k,),
                )
                if cur.rowcount == 1:
                    inserted += 1

    return jsonify({"ok": True, "eklenen": inserted, "toplam_gelen": len(keys)})

if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port)
