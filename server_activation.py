from flask import Flask, request, jsonify
import jwt
import time
import json
import os
from datetime import datetime, timezone

# -------------------------------
# CONFIGURACIÓN
# -------------------------------

SECRET_KEY = "03C00218044D05A9B706300700080009"   # 🔒 Cambia esto a una cadena segura
ADMIN_TOKEN = "admin123"             # 🔑 Token que usarás en admin_cli.py
HWID_FILE = "allowed_hwids.json"     # Archivo local donde se guardan los HWIDs
TOKEN_EXPIRATION = 24 * 3600         # (Opcional) segundos que dura un token JWT (1 día)

app = Flask(__name__)

# -------------------------------
# FUNCIONES AUXILIARES
# -------------------------------

def now_ts():
    return int(time.time())

def parse_expires(expires):
    """
    Acepta:
      - None -> devuelve None
      - int (timestamp) -> devuelve int
      - str con formato ISO -> convierte a timestamp
    """
    if expires is None:
        return None
    try:
        return int(expires)
    except Exception:
        pass
    try:
        dt = datetime.fromisoformat(expires)
        return int(dt.replace(tzinfo=timezone.utc).timestamp())
    except Exception:
        pass
    return None

def load_hwids_struct():
    """Devuelve lista de dicts: [{'hwid':..., 'expires':timestamp_or_none}, ...]"""
    if not os.path.exists(HWID_FILE):
        with open(HWID_FILE, "w") as f:
            json.dump([], f)
    with open(HWID_FILE, "r") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            data = []
    # migración: lista simple de strings → lista de dicts
    if data and isinstance(data[0], str):
        new = [{"hwid": h, "expires": None} for h in data]
        with open(HWID_FILE, "w") as f:
            json.dump(new, f, indent=2)
        return new
    return data

def save_hwids_struct(lst):
    with open(HWID_FILE, "w") as f:
        json.dump(lst, f, indent=2)

def is_expired(item):
    exp = item.get("expires")
    if not exp:
        return False
    return int(time.time()) > int(exp)

def find_hwid(hwid):
    for item in load_hwids_struct():
        if item.get("hwid") == hwid:
            return item
    return None

# -------------------------------
# RUTA: ACTIVAR
# -------------------------------

@app.route("/activar", methods=["POST"])
def activar():
    data = request.json or {}
    hwid = data.get("hwid")
    if not hwid:
        return jsonify({"ok": False, "error": "no_hwid"}), 400

    item = find_hwid(hwid)
    if not item:
        return jsonify({"ok": False, "error": "hwid_not_allowed"}), 403
    if is_expired(item):
        return jsonify({"ok": False, "error": "hwid_expired"}), 403

    # Crear token JWT válido 24h
    payload = {
        "hwid": hwid,
        "exp": int(time.time()) + TOKEN_EXPIRATION
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return jsonify({"ok": True, "token": token})

# -------------------------------
# RUTA: VERIFICAR TOKEN
# -------------------------------

@app.route("/verificar", methods=["POST"])
def verificar():
    data = request.json or {}
    token = data.get("token")
    if not token:
        return jsonify({"valid": False, "error": "no_token"}), 400

    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return jsonify({"valid": True, "data": decoded})
    except jwt.ExpiredSignatureError:
        return jsonify({"valid": False, "error": "expired"})
    except jwt.InvalidTokenError:
        return jsonify({"valid": False, "error": "invalid"})

# -------------------------------
# ADMIN: LISTAR HWIDs
# -------------------------------

@app.route("/admin/list_hwids", methods=["GET"])
def admin_list_hwids():
    token = request.headers.get("X-Admin-Token")
    if token != ADMIN_TOKEN:
        return jsonify({"error": "unauthorized"}), 401

    lst = load_hwids_struct()
    out = []
    for item in lst:
        out.append({
            "hwid": item.get("hwid"),
            "expires": item.get("expires"),
            "expired": is_expired(item)
        })
    return jsonify({"hwids": out})

# -------------------------------
# ADMIN: AGREGAR / ACTUALIZAR HWID
# -------------------------------

@app.route("/admin/add_or_update_hwid", methods=["POST"])
def admin_add_or_update_hwid():
    token = request.headers.get("X-Admin-Token")
    if token != ADMIN_TOKEN:
        return jsonify({"error": "unauthorized"}), 401

    data = request.json or {}
    hwid = data.get("hwid")
    if not hwid:
        return jsonify({"ok": False, "error": "no_hwid"}), 400

    lst = load_hwids_struct()

    # calcular fecha de expiración
    expires = None
    if "days" in data:
        try:
            days = int(data.get("days", 0))
            expires = int(time.time()) + days * 24 * 3600
        except Exception:
            expires = None
    elif "expires" in data:
        expires = parse_expires(data.get("expires"))

    found = None
    for it in lst:
        if it.get("hwid") == hwid:
            found = it
            break

    if found:
        found["expires"] = expires
        save_hwids_struct(lst)
        return jsonify({"ok": True, "message": "updated", "hwid": hwid, "expires": expires})
    else:
        lst.append({"hwid": hwid, "expires": expires})
        save_hwids_struct(lst)
        return jsonify({"ok": True, "message": "added", "hwid": hwid, "expires": expires})

# -------------------------------
# ADMIN: ELIMINAR HWID
# -------------------------------

@app.route("/admin/remove_hwid", methods=["POST"])
def admin_remove_hwid():
    token = request.headers.get("X-Admin-Token")
    if token != ADMIN_TOKEN:
        return jsonify({"error": "unauthorized"}), 401

    data = request.json or {}
    hwid = data.get("hwid")
    if not hwid:
        return jsonify({"ok": False, "error": "no_hwid"}), 400

    lst = load_hwids_struct()
    new = [it for it in lst if it.get("hwid") != hwid]
    if len(new) == len(lst):
        return jsonify({"ok": False, "message": "not_found"}), 404
    save_hwids_struct(new)
    return jsonify({"ok": True, "message": "removed", "hwid": hwid})

# -------------------------------
# INICIO DEL SERVIDOR
# -------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    print(f"Servidor de activación corriendo en http://0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port)
