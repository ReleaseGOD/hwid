from flask import Flask, request, jsonify
import jwt, datetime, json, os

app = Flask(__name__)

SECRET = "MI_CLAVE_SECRETA_SUPERSEGURA"  # cámbiala y guárdala fuera del repo en producción
HWID_FILE = "allowed_hwids.json"

def cargar_hwids():
    if not os.path.exists(HWID_FILE):
        # crea el archivo con una lista vacía si no existe
        with open(HWID_FILE, "w") as f:
            json.dump([], f)
    with open(HWID_FILE, "r") as f:
        return json.load(f)

def guardar_hwids(hwids):
    with open(HWID_FILE, "w") as f:
        json.dump(hwids, f, indent=2)

@app.route("/activar", methods=["POST"])
def activar():
    data = request.json or {}
    hwid = data.get("hwid")
    if not hwid:
        return jsonify({"error": "No se envió HWID"}), 400

    allowed = cargar_hwids()
    if hwid not in allowed:
        return jsonify({"error": "HWID no autorizado"}), 403

    token = jwt.encode(
        {"hwid": hwid, "exp": datetime.datetime.utcnow() + datetime.timedelta(days=30)},
        SECRET,
        algorithm="HS256"
    )
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

# Endpoint simple para añadir HWID (solo local/admin). No expongas esto sin auth en producción.
@app.route("/admin/add_hwid", methods=["POST"])
def add_hwid():
    data = request.json or {}
    hwid = data.get("hwid")
    if not hwid:
        return jsonify({"error": "No se envió HWID"}), 400
    hwids = cargar_hwids()
    if hwid in hwids:
        return jsonify({"ok": False, "message": "HWID ya existe"})
    hwids.append(hwid)
    guardar_hwids(hwids)
    return jsonify({"ok": True, "message": "HWID agregado"})

@app.route("/", methods=["GET"])
def home():
    return jsonify({"status": "ok", "message": "Servidor de activación funcionando 🚀"})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"Servidor de activación corriendo en http://0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port)
