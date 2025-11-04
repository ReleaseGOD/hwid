from flask import Flask, request, jsonify
import jwt, datetime, requests, base64, json, os

app = Flask(__name__)

SECRET = "03C00218044D05A9B706300700080009"
ADMIN_TOKEN = "admin123"

# Datos de GitHub (se leen desde variables de entorno)
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_REPO = os.getenv("GITHUB_REPO", "ReleaseGOD/hwid")
GITHUB_FILE = os.getenv("GITHUB_FILE", "allowed_hwids.json")

HEADERS = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github.v3+json"
}

# ======================================================
# 🔧 Funciones auxiliares
# ======================================================
def github_api_url():
    return f"https://api.github.com/repos/{GITHUB_REPO}/contents/{GITHUB_FILE}"

def cargar_hwids():
    """Descarga el archivo JSON de GitHub"""
    resp = requests.get(github_api_url(), headers=HEADERS)
    if resp.status_code == 200:
        content = resp.json()
        data = base64.b64decode(content["content"]).decode("utf-8")
        try:
            return json.loads(data)
        except:
            return []
    else:
        return []

def guardar_hwids(hwids, mensaje="Actualizando HWIDs"):
    """Sube el archivo JSON a GitHub"""
    current = requests.get(github_api_url(), headers=HEADERS).json()
    sha = current.get("sha")

    new_content = json.dumps(hwids, indent=2)
    encoded = base64.b64encode(new_content.encode("utf-8")).decode("utf-8")

    payload = {
        "message": mensaje,
        "content": encoded,
        "sha": sha
    }

    resp = requests.put(github_api_url(), headers=HEADERS, json=payload)
    return resp.status_code in [200, 201]

# ======================================================
# 🔑 Rutas de activación
# ======================================================
@app.route("/activar", methods=["POST"])
def activar():
    data = request.json or {}
    hwid = data.get("hwid")
    if not hwid:
        return jsonify({"error": "No se envió HWID"}), 400

    allowed = cargar_hwids()
    entry = next((x for x in allowed if x["hwid"] == hwid), None)
    if not entry:
        return jsonify({"error": "HWID no autorizado"}), 403

    exp_date = datetime.datetime.fromisoformat(entry["exp"])
    if datetime.datetime.utcnow() > exp_date:
        return jsonify({"error": "Licencia expirada"}), 403

    token = jwt.encode(
        {"hwid": hwid, "exp": exp_date},
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

# ======================================================
# 🛠️ Rutas de administración (con token)
# ======================================================
def check_admin(req):
    token = req.headers.get("X-Admin-Token")
    return token == ADMIN_TOKEN

@app.route("/admin/list", methods=["GET"])
def list_hwids():
    if not check_admin(request):
        return jsonify({"error": "No autorizado"}), 403
    return jsonify(cargar_hwids())

@app.route("/admin/add", methods=["POST"])
def add_hwid():
    if not check_admin(request):
        return jsonify({"error": "No autorizado"}), 403

    data = request.json or {}
    hwid = data.get("hwid")
    days = int(data.get("days", 30))
    if not hwid:
        return jsonify({"error": "No se envió HWID"}), 400

    hwids = cargar_hwids()
    exp_date = (datetime.datetime.utcnow() + datetime.timedelta(days=days)).date().isoformat()

    existing = next((x for x in hwids if x["hwid"] == hwid), None)
    if existing:
        existing["exp"] = exp_date
        msg = "HWID actualizado"
    else:
        hwids.append({"hwid": hwid, "exp": exp_date})
        msg = "HWID agregado"

    ok = guardar_hwids(hwids, msg)
    return jsonify({"ok": ok, "message": msg, "exp": exp_date})

@app.route("/admin/remove", methods=["POST"])
def remove_hwid():
    if not check_admin(request):
        return jsonify({"error": "No autorizado"}), 403

    data = request.json or {}
    hwid = data.get("hwid")
    if not hwid:
        return jsonify({"error": "No se envió HWID"}), 400

    hwids = cargar_hwids()
    new_list = [h for h in hwids if h["hwid"] != hwid]

    if len(new_list) == len(hwids):
        return jsonify({"error": "HWID no encontrado"}), 404

    ok = guardar_hwids(new_list, f"Eliminado HWID {hwid}")
    return jsonify({"ok": ok, "message": "HWID eliminado"})

# ======================================================
# 🚀 Inicio del servidor
# ======================================================
if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    print(f"Servidor activo en http://0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port)
