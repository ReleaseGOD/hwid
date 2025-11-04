from flask import Flask, request, jsonify
import jwt, datetime, json, os

app = Flask(__name__)

SECRET = "03C00218044D05A9B706300700080009"  # cámbiala por una clave segura
ADMIN_TOKEN = "admin123"  # token simple para proteger las rutas admin
HWID_FILE = "allowed_hwids.json"

# === UTILIDADES ===

def cargar_hwids():
    if not os.path.exists(HWID_FILE):
        with open(HWID_FILE, "w") as f:
            json.dump([], f)
    with open(HWID_FILE, "r") as f:
        return json.load(f)

def guardar_hwids(hwids):
    with open(HWID_FILE, "w") as f:
        json.dump(hwids, f, indent=2)

def buscar_hwid(hwids, hwid):
    for item in hwids:
        if item["hwid"] == hwid:
            return item
    return None

def auth_admin(req):
    token = req.headers.get("Authorization", "").replace("Bearer ", "")
    return token == ADMIN_TOKEN

# === ENDPOINTS PRINCIPALES ===

@app.route("/activar", methods=["POST"])
def activar():
    data = request.json or {}
    hwid = data.get("hwid")
    if not hwid:
        return jsonify({"error": "No se envió HWID"}), 400

    hwids = cargar_hwids()
    registro = buscar_hwid(hwids, hwid)
    if not registro:
        return jsonify({"error": "HWID no autorizado"}), 403

    exp = datetime.datetime.strptime(registro["exp"], "%Y-%m-%d") if "exp" in registro else datetime.datetime.utcnow() + datetime.timedelta(days=30)
    token = jwt.encode({"hwid": hwid, "exp": exp}, SECRET, algorithm="HS256")
    return jsonify({"license": token})

@app.route("/verificar", methods=["POST"])
def verificar():
    data = request.json or {}
    token = data.get("token")
    try:
        info = jwt.decode(token, SECRET, algorithms=["HS256"])
        return jsonify({"valid": True, "data": info})
    except jwt.ExpiredSignatureError:
        return jsonify({"valid": False, "error": "Licencia expirada"})
    except Exception:
        return jsonify({"valid": False, "error": "Licencia inválida"})

# === ENDPOINTS ADMIN ===

@app.route("/admin/add_hwid", methods=["POST"])
def add_hwid():
    if not auth_admin(request):
        return jsonify({"error": "No autorizado"}), 403

    data = request.json or {}
    hwid = data.get("hwid")
    days = int(data.get("days", 30))
    if not hwid:
        return jsonify({"error": "No se envió HWID"}), 400

    hwids = cargar_hwids()
    if buscar_hwid(hwids, hwid):
        return jsonify({"ok": False, "message": "HWID ya existe"})

    exp = (datetime.datetime.utcnow() + datetime.timedelta(days=days)).strftime("%Y-%m-%d")
    hwids.append({"hwid": hwid, "exp": exp})
    guardar_hwids(hwids)
    return jsonify({"ok": True, "message": f"HWID agregado con expiración {exp}"})

@app.route("/admin/list_hwids", methods=["GET"])
def list_hwids():
    if not auth_admin(request):
        return jsonify({"error": "No autorizado"}), 403
    hwids = cargar_hwids()
    return jsonify(hwids)

@app.route("/admin/remove_hwid", methods=["POST"])
def remove_hwid():
    if not auth_admin(request):
        return jsonify({"error": "No autorizado"}), 403
    data = request.json or {}
    hwid = data.get("hwid")
    if not hwid:
        return jsonify({"error": "No se envió HWID"}), 400

    hwids = cargar_hwids()
    updated = [h for h in hwids if h["hwid"] != hwid]
    guardar_hwids(updated)
    return jsonify({"ok": True, "message": f"HWID {hwid} eliminado"})

@app.route("/admin/update_hwid", methods=["POST"])
def update_hwid():
    if not auth_admin(request):
        return jsonify({"error": "No autorizado"}), 403
    data = request.json or {}
    hwid = data.get("hwid")
    days = int(data.get("days", 30))
    if not hwid:
        return jsonify({"error": "No se envió HWID"}), 400

    hwids = cargar_hwids()
    registro = buscar_hwid(hwids, hwid)
    if not registro:
        return jsonify({"error": "HWID no encontrado"}), 404

    registro["exp"] = (datetime.datetime.utcnow() + datetime.timedelta(days=days)).strftime("%Y-%m-%d")
    guardar_hwids(hwids)
    return jsonify({"ok": True, "message": f"Expiración actualizada a {registro['exp']}"})

# === MAIN ===

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"Servidor corriendo en http://0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port)
